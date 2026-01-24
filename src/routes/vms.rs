use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::cgroups;
use crate::client::send_patch_request;
use crate::config::{SnapshotCreate, SnapshotLoad, VmState};
use crate::dtos::{DeleteVmRequest, DeployVmRequest, RestoreRequest, StopVmRequest, VmIdRequest, VmStatus};
use crate::{AppState, MicroVM, INSTANCE_DIR, KERNEL_PATH, SNAPSHOTS_DIR, prepare_instance_drive};

pub async fn deploy_vm(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeployVmRequest>,
) -> impl IntoResponse {
    let vm_id = payload.vm_id.clone();

    // Validate vm_id
    if vm_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "vm_id cannot be empty".to_string()).into_response();
    }

    // TAP device names have a 15 character limit in Linux
    if vm_id.len() > 15 {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "vm_id too long (max 15 chars, got {}). Linux TAP device name limit.",
                vm_id.len()
            ),
        )
            .into_response();
    }

    // Only allow alphanumeric and dashes (safe for TAP device names)
    if !vm_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return (
            StatusCode::BAD_REQUEST,
            "vm_id can only contain alphanumeric characters and dashes".to_string(),
        )
            .into_response();
    }

    // Assign Ip
    let octet = {
        let mut ip_lock = state.ipam.lock().await;
        match ip_lock.allocate() {
            Some(i) => i,
            None => return (StatusCode::SERVICE_UNAVAILABLE, "Subnet Full").into_response(),
        }
    };
    let guest_ip = format!("172.16.0.{}", octet);
    let gateway_ip = "172.16.0.1";
    let tap_name = vm_id.clone(); // Use vm_id directly as TAP name

    println!("🛸 Deploying VM with ID: {} and IP: {}", vm_id, guest_ip);

    // Setup Cgroup (before spawning process)
    if let Err(e) = cgroups::create_vm_cgroup(&vm_id) {
        eprintln!("⚠️ Cgroup creation failed: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Cgroup Error: {}", e),
        )
            .into_response();
    }

    // Apply resource limits: 20% CPU (20000), 128MB RAM
    if let Err(e) = cgroups::apply_limits(&vm_id, 20000, 128 * 1024 * 1024) {
        eprintln!("⚠️ Cgroup limits failed: {}", e);
        let _ = cgroups::remove_vm_cgroup(&vm_id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Cgroup Limits Error: {}", e),
        )
            .into_response();
    }

    // Create DB Record (Mark as 'starting')
    let vm_uuid = uuid::Uuid::parse_str(&vm_id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO vms (id, name, status, ip_address, tap_interface)
        VALUES ($1, $2, 'starting', $3, $4)
        "#,
        vm_uuid,
        vm_id,
        guest_ip,
        tap_name
    )
    .execute(&state.db)
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB Error: {}", e),
        )
            .into_response();
    }

    // 1. Host Network Plumbing using native APIs
    if let Err(e) = state
        .network_manager
        .setup_tap_bridge(&tap_name, "br0")
        .await
    {
        // Mark as failed in DB and free IP
        println!("❌ Deployment failed at network setup, marking as 'failed' in DB");
        state.ipam.lock().await.free(octet);
        if let Err(db_err) = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await
        {
            eprintln!("⚠️ Failed to update DB status: {}", db_err);
        }

        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Net Error: {}", e),
        )
            .into_response();
    }

    // 2. Instantiate VM Struct
    // Note: We use the constants or payload data here
    let mut vm = MicroVM::new(&vm_id, &tap_name, &guest_ip, gateway_ip, octet);

    // 3. Spawn Process
    if let Err(e) = vm.start_process().await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await; // Cleanup TAP
        let _ = cgroups::remove_vm_cgroup(&vm_id); // Cleanup cgroup
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await;
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Move the spawned process into the cgroup
    let pid = vm
        .process
        .as_ref()
        .and_then(|p| p.id())
        .ok_or_else(|| anyhow::anyhow!("Failed to get process ID"));

    match pid {
        Ok(pid) => {
            if let Err(e) = cgroups::add_process(&vm_id, pid) {
                eprintln!("⚠️ Failed to jail process: {}", e);
                // Kill the VM since it's running unconstrained
                state.ipam.lock().await.free(octet);
                let _ = vm.cleanup(&state.network_manager).await;
                let _ = sqlx::query!(
                    r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
                    vm_id
                )
                .execute(&state.db)
                .await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Cgroup Process Jail Error: {}", e),
                )
                    .into_response();
            }
        }
        Err(e) => {
            eprintln!("⚠️ Failed to get process ID: {}", e);
            state.ipam.lock().await.free(octet);
            let _ = vm.cleanup(&state.network_manager).await;
            let _ = sqlx::query!(
                r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
                vm_id
            )
            .execute(&state.db)
            .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get process ID".to_string(),
            )
                .into_response();
        }
    }

    // 4. Configure Resources (CPU/RAM)
    if let Err(e) = vm.configure_vm().await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await; // Cleanup TAP
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await;
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // 5. The Sequence You Asked About (Yes, it goes here!)
    // We await each step. If one fails, we return Error immediately.

    // Set Boot Source
    if let Err(e) = vm.set_boot_source(KERNEL_PATH).await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await; // Cleanup TAP
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Boot Source Error: {}", e),
        )
            .into_response();
    }

    // Prepare unique rootfs drive for this VM (copies the base image)
    let rootfs_path = match prepare_instance_drive(&vm_id).await {
        Ok(path) => path,
        Err(e) => {
            state.ipam.lock().await.free(octet);
            let _ = state.network_manager.teardown_tap(&tap_name).await; // Cleanup TAP
            let _ = sqlx::query!(
                r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
                vm_id
            )
            .execute(&state.db)
            .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to prepare instance drive: {}", e),
            )
                .into_response();
        }
    };

    // Attach Drive
    if let Err(e) = vm.attach_rootfs(&rootfs_path).await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await; // Cleanup TAP
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("RootFS Error: {}", e),
        )
            .into_response();
    }

    // Attach Network (Guest Side)
    if let Err(e) = vm.attach_network().await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await; // Cleanup TAP
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Net Attach Error: {}", e),
        )
            .into_response();
    }

    // 6. Ignite
    if let Err(e) = vm.start_instance().await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await; // Cleanup TAP
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Start Error: {}", e),
        )
            .into_response();
    }

    // 7. Health Check - Verify VM actually booted successfully
    println!("🩺 Performing Health Check...");

    // Wait a moment for early crashes (file lock errors happen fast)
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Check if the Child Process is still running
    let is_alive = match vm.process.as_mut() {
        Some(child) => {
            // try_wait() returns Ok(None) if running, Ok(Some(status)) if exited
            match child.try_wait() {
                Ok(None) => true, // Still running!
                Ok(Some(status)) => {
                    println!("❌ VM Crashed immediately! Exit Code: {}", status);
                    false
                }
                Err(e) => {
                    println!("⚠️ Failed to check VM status: {}", e);
                    false
                }
            }
        }
        None => false,
    };

    if !is_alive {
        // Cleanup the failed TAP device
        let _ = state.network_manager.teardown_tap(&tap_name).await;

        // Free the IP
        state.ipam.lock().await.free(octet);

        // Mark VM as failed in database and clear IP
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await;

        // Return error to user
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "VM crashed during boot (check server logs)".to_string(),
        )
            .into_response();
    }

    // Update DB Record (Mark as 'running')
    sqlx::query!(
        r#"UPDATE vms SET status = 'running' WHERE name = $1"#,
        vm_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        eprintln!("⚠️ Warning: Failed to update DB status: {}", e);
    })
    .ok();

    // 8. Success! NOW we save state and return 200
    state.vms.lock().await.insert(vm_id.clone(), vm);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "deployed", "id": vm_id, "ip": guest_ip })),
    )
        .into_response()
}

pub async fn stop_vm(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<StopVmRequest>,
) -> impl IntoResponse {
    let vm_id = payload.vm_id;
    println!("🛑 Received Stop/Terminate Request for: {}", vm_id);

    // Fetch snapshot files before deleting (CASCADE will delete snapshot records)
    let snapshots = sqlx::query!(
        r#"SELECT snapshot_path, mem_file_path as "mem_file_path?" FROM snapshots WHERE vm_id = $1"#,
        vm_id
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let vm_opt = state.vms.lock().await.remove(&vm_id);

    match vm_opt {
        Some(mut vm) => {
            let octet = vm.ip_octet;
            state.ipam.lock().await.free(octet);
            if let Err(e) = vm.cleanup(&state.network_manager).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to stop VM: {}", e),
                )
                    .into_response();
            }

            // Delete from database (CASCADE will delete snapshot records)
            let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, vm_id)
                .execute(&state.db)
                .await;

            // Clean up snapshot files from disk
            println!("   Cleaning up {} snapshot file(s)...", snapshots.len());
            for snapshot in snapshots {
                if std::path::Path::new(&snapshot.snapshot_path).exists() {
                    let _ = tokio::fs::remove_file(&snapshot.snapshot_path).await;
                }
                if let Some(mem_path) = snapshot.mem_file_path {
                    if std::path::Path::new(&mem_path).exists() {
                        let _ = tokio::fs::remove_file(&mem_path).await;
                    }
                }
            }

            // Clean up VM disk file
            let disk_path = format!("{}/rootfs-{}.ext4", INSTANCE_DIR, vm_id);
            if std::path::Path::new(&disk_path).exists() {
                let _ = tokio::fs::remove_file(&disk_path).await;
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "deleted", "id": vm_id })),
            )
                .into_response()
        }
        None => {
            // VM not in memory, but might be in DB (paused/stopped)
            // Just delete from DB and cleanup files
            let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, vm_id)
                .execute(&state.db)
                .await;

            // Clean up snapshot files from disk
            for snapshot in snapshots {
                if std::path::Path::new(&snapshot.snapshot_path).exists() {
                    let _ = tokio::fs::remove_file(&snapshot.snapshot_path).await;
                }
                if let Some(mem_path) = snapshot.mem_file_path {
                    if std::path::Path::new(&mem_path).exists() {
                        let _ = tokio::fs::remove_file(&mem_path).await;
                    }
                }
            }

            // Clean up VM disk file
            let disk_path = format!("{}/rootfs-{}.ext4", INSTANCE_DIR, vm_id);
            if std::path::Path::new(&disk_path).exists() {
                let _ = tokio::fs::remove_file(&disk_path).await;
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "deleted", "id": vm_id })),
            )
                .into_response()
        }
    }
}

pub async fn delete_vm(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeleteVmRequest>,
) -> impl IntoResponse {
    let vm_id = payload.vm_id;
    println!("🗑️  Received Delete Request for: {}", vm_id);

    // Fetch snapshot files before deleting (CASCADE will delete snapshot records)
    let snapshots = sqlx::query!(
        r#"SELECT snapshot_path, mem_file_path as "mem_file_path?" FROM snapshots WHERE vm_id = $1"#,
        vm_id
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // Delete from database (CASCADE will delete snapshots table entries)
    let result = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, vm_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                // Clean up snapshot files from disk
                println!("   Cleaning up {} snapshot file(s)...", snapshots.len());
                for snapshot in snapshots {
                    if std::path::Path::new(&snapshot.snapshot_path).exists() {
                        let _ = tokio::fs::remove_file(&snapshot.snapshot_path).await;
                    }
                    if let Some(mem_path) = snapshot.mem_file_path {
                        if std::path::Path::new(&mem_path).exists() {
                            let _ = tokio::fs::remove_file(&mem_path).await;
                        }
                    }
                }

                // Clean up snapshot directory if it exists
                let snapshot_dir = format!("{}/{}", SNAPSHOTS_DIR, vm_id);
                let disk_snapshot_dir = format!("{}/disk-snapshots/{}", SNAPSHOTS_DIR, vm_id);

                if std::path::Path::new(&snapshot_dir).exists() {
                    let _ = tokio::fs::remove_dir_all(&snapshot_dir).await;
                }
                if std::path::Path::new(&disk_snapshot_dir).exists() {
                    let _ = tokio::fs::remove_dir_all(&disk_snapshot_dir).await;
                }

                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "status": "deleted", "id": vm_id })),
                )
                    .into_response()
            } else {
                (StatusCode::NOT_FOUND, "VM Not Found").into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response(),
    }
}

pub async fn list_vms(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Query database for all VMs with snapshot name if applicable
    // Only join with user snapshots (not temp snapshots)
    let rows = sqlx::query!(
        r#"
        SELECT v.id, v.name, v.status, v.ip_address, v.tap_interface, v.created_from_snapshot_id,
               s.name as "snapshot_name?"
        FROM vms v
        LEFT JOIN snapshots s ON v.created_from_snapshot_id = s.id AND s.snapshot_type = 'user'
        ORDER BY v.created_at DESC
        "#
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let vms: Vec<VmStatus> = rows
        .into_iter()
        .map(|row| {
            // Try to get stats for running VMs
            let stats = if row.status == "running" {
                cgroups::get_stats(&row.name).ok()
            } else {
                None
            };

            VmStatus {
                id: row.name,
                ip: row.ip_address.unwrap_or_else(|| "N/A".to_string()),
                status: row.status,
                tap: row.tap_interface.unwrap_or_else(|| "N/A".to_string()),
                stats,
                created_from_snapshot_id: row.created_from_snapshot_id.map(|uuid| uuid.to_string()),
                snapshot_name: row.snapshot_name,
            }
        })
        .collect();

    (StatusCode::OK, Json(vms)).into_response()
}

pub async fn pause_vm(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VmIdRequest>,
) -> impl IntoResponse {
    let vm_id = req.vm_id;

    // Get VM from HashMap
    let vms = state.vms.lock().await;
    let vm = match vms.get(&vm_id) {
        Some(vm) => vm,
        None => return (StatusCode::NOT_FOUND, "VM not found".to_string()).into_response(),
    };

    // Check if VM is in a pausable state (should be running)
    let current_status = sqlx::query!(
        r#"SELECT status FROM vms WHERE name = $1"#,
        vm_id
    )
    .fetch_optional(&state.db)
    .await;

    match current_status {
        Ok(Some(record)) => {
            if record.status != "running" {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("VM must be running to pause (current status: {})", record.status),
                )
                    .into_response();
            }
        }
        Ok(None) => return (StatusCode::NOT_FOUND, "VM not found in database".to_string()).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response(),
    }

    // Send PATCH request to pause the VM
    let vm_state = VmState {
        state: "Paused".to_string(),
    };

    match send_patch_request(&vm.socket_path, "/vm", &vm_state).await {
        Ok(response) => {
            if !response.contains("HTTP/1.1 2") {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to pause VM: {}", response.lines().next().unwrap_or("Unknown error")),
                )
                    .into_response();
            }

            // Create temporary full snapshot for resume
            let snapshot_dir = format!("{}/{}", SNAPSHOTS_DIR, vm_id);
            if let Err(e) = tokio::fs::create_dir_all(&snapshot_dir).await {
                eprintln!("⚠️ Failed to create snapshot directory: {}", e);
            } else {
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let snap_path = format!("{}/snap_{}", snapshot_dir, timestamp);
                let mem_path = format!("{}/mem_{}", snapshot_dir, timestamp);

                let snapshot_req = SnapshotCreate {
                    snapshot_type: "Full".to_string(),
                    snapshot_path: snap_path.clone(),
                    mem_file_path: mem_path.clone(),
                };

                if let Ok(_) = crate::client::send_put_request(&vm.socket_path, "/snapshot/create", &snapshot_req).await {
                    let snap_size = tokio::fs::metadata(&snap_path).await.map(|m| m.len()).unwrap_or(0);
                    let mem_size = tokio::fs::metadata(&mem_path).await.map(|m| m.len()).unwrap_or(0);
                    let total_size_mb = ((snap_size + mem_size) / 1_048_576) as i32;

                    // Move temp snapshot to aether-instances directory
                    let instance_snap_dir = format!("{}/{}", INSTANCE_DIR, vm_id);
                    let _ = tokio::fs::create_dir_all(&instance_snap_dir).await;

                    let final_snap_path = format!("{}/snap_{}", instance_snap_dir, timestamp);
                    let final_mem_path = format!("{}/mem_{}", instance_snap_dir, timestamp);

                    // Copy files to aether-instances
                    let mut snap_moved = false;
                    let mut mem_moved = false;

                    if let Ok(_) = tokio::fs::copy(&snap_path, &final_snap_path).await {
                        let _ = tokio::fs::remove_file(&snap_path).await;
                        snap_moved = true;
                    }
                    if let Ok(_) = tokio::fs::copy(&mem_path, &final_mem_path).await {
                        let _ = tokio::fs::remove_file(&mem_path).await;
                        mem_moved = true;
                    }

                    // Use final paths if moved, otherwise keep original
                    let db_snap_path = if snap_moved { final_snap_path } else { snap_path };
                    let db_mem_path = if mem_moved { final_mem_path } else { mem_path };

                    let snapshot_id = uuid::Uuid::new_v4();
                    let snapshot_name = format!("temp-pause-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));

                    let _ = sqlx::query!(
                        r#"
                        INSERT INTO snapshots (id, vm_id, name, snapshot_path, mem_file_path, created_at, file_size_mb, snapshot_type)
                        VALUES ($1, $2, $3, $4, $5, NOW(), $6, 'temp')
                        "#,
                        snapshot_id,
                        vm_id,
                        snapshot_name,
                        db_snap_path,
                        db_mem_path,
                        total_size_mb
                    )
                    .execute(&state.db)
                    .await;

                    // Clean up empty snapshot directory if both files moved
                    if snap_moved && mem_moved {
                        let _ = tokio::fs::remove_dir(&snapshot_dir).await;
                    }
                }
            }

            // Update database status to 'paused'
            if let Err(e) = sqlx::query!(
                r#"UPDATE vms SET status = 'paused' WHERE name = $1"#,
                vm_id
            )
            .execute(&state.db)
            .await
            {
                eprintln!("⚠️ Warning: Failed to update DB status: {}", e);
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "paused", "id": vm_id })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to communicate with VM: {}", e),
        )
            .into_response(),
    }
}

pub async fn resume_vm(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VmIdRequest>,
) -> impl IntoResponse {
    let vm_id = req.vm_id.clone();

    // Check if VM is paused in database
    let current_status = sqlx::query!(
        r#"SELECT status FROM vms WHERE name = $1"#,
        vm_id
    )
    .fetch_optional(&state.db)
    .await;

    match current_status {
        Ok(Some(record)) => {
            if record.status != "paused" {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("VM must be paused to resume (current status: {})", record.status),
                )
                    .into_response();
            }
        }
        Ok(None) => return (StatusCode::NOT_FOUND, "VM not found in database".to_string()).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response(),
    }

    // Check if VM is in memory (process still running but paused)
    let vm_in_memory = state.vms.lock().await.contains_key(&vm_id);

    if vm_in_memory {
        // VM process is still running, just send resume signal
        let vms = state.vms.lock().await;
        let vm = vms.get(&vm_id).unwrap();

        let vm_state = VmState {
            state: "Resumed".to_string(),
        };

        match send_patch_request(&vm.socket_path, "/vm", &vm_state).await {
            Ok(response) => {
                if !response.contains("HTTP/1.1 2") {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to resume VM: {}", response.lines().next().unwrap_or("Unknown error")),
                    )
                        .into_response();
                }

                let _ = sqlx::query!(
                    r#"UPDATE vms SET status = 'running' WHERE name = $1"#,
                    vm_id
                )
                .execute(&state.db)
                .await;

                // Cleanup temporary pause snapshots
                if let Ok(temp_snapshots) = sqlx::query!(
                    r#"
                    SELECT snapshot_path, mem_file_path
                    FROM snapshots
                    WHERE vm_id = $1 AND snapshot_type = 'temp'
                    "#,
                    vm_id
                )
                .fetch_all(&state.db)
                .await {
                    for snap in temp_snapshots {
                        if std::path::Path::new(&snap.snapshot_path).exists() {
                            let _ = tokio::fs::remove_file(&snap.snapshot_path).await;
                        }
                        if let Some(mem_path) = snap.mem_file_path {
                            if std::path::Path::new(&mem_path).exists() {
                                let _ = tokio::fs::remove_file(&mem_path).await;
                            }
                        }
                    }

                    let _ = sqlx::query!(
                        r#"DELETE FROM snapshots WHERE vm_id = $1 AND snapshot_type = 'temp'"#,
                        vm_id
                    )
                    .execute(&state.db)
                    .await;
                }

                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "status": "running", "id": vm_id })),
                )
                    .into_response()
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to communicate with VM: {}", e),
            )
                .into_response(),
        }
    } else {
        // VM process not in memory - must restore from full snapshot
        let snapshot = match sqlx::query!(
            r#"
            SELECT id, snapshot_path, mem_file_path
            FROM snapshots
            WHERE vm_id = $1 AND mem_file_path IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            vm_id
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(record)) => record,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    format!("No full VM snapshot found for paused VM '{}'. Cannot resume.", vm_id),
                )
                    .into_response();
            }
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response();
            }
        };

        // Restore from snapshot
        let restore_req = RestoreRequest {
            snapshot_id: snapshot.id.to_string(),
            new_vm_id: vm_id.clone(),
        };

        return restore_vm(State(state), Json(restore_req)).await.into_response();
    }
}

pub async fn restore_vm(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RestoreRequest>,
) -> impl IntoResponse {
    let new_vm_id = req.new_vm_id.clone();

    // Validate new_vm_id
    if new_vm_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "new_vm_id cannot be empty".to_string()).into_response();
    }

    if new_vm_id.len() > 15 {
        return (
            StatusCode::BAD_REQUEST,
            format!("new_vm_id too long (max 15 chars, got {})", new_vm_id.len()),
        )
            .into_response();
    }

    if !new_vm_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return (
            StatusCode::BAD_REQUEST,
            "new_vm_id can only contain alphanumeric characters and dashes".to_string(),
        )
            .into_response();
    }

    // Check if VM already exists in memory (running)
    let vm_in_memory = state.vms.lock().await.contains_key(&new_vm_id);

    // Check if VM exists in DB
    let vm_in_db = sqlx::query!(
        r#"SELECT status FROM vms WHERE name = $1"#,
        new_vm_id
    )
    .fetch_optional(&state.db)
    .await;

    // Track if this is a resume operation (paused VM being restored)
    let is_resume = matches!(
        &vm_in_db,
        Ok(Some(record)) if record.status == "paused"
    );

    match (vm_in_memory, vm_in_db) {
        (true, _) => {
            return (StatusCode::CONFLICT, "VM is currently running".to_string()).into_response();
        }
        (false, Ok(Some(record))) if record.status != "paused" => {
            return (
                StatusCode::CONFLICT,
                format!("VM exists in database with status: {}", record.status),
            )
                .into_response();
        }
        (false, Ok(Some(_))) if is_resume => {
            // VM is paused - this is a resume operation
        }
        (false, Ok(None)) => {
            // VM doesn't exist - normal restore operation
        }
        (false, Err(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response();
        }
        _ => {}
    }

    // Parse snapshot UUID
    let snapshot_uuid = match uuid::Uuid::parse_str(&req.snapshot_id) {
        Ok(uuid) => uuid,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid snapshot ID format".to_string()).into_response();
        }
    };

    // Fetch snapshot metadata from database (including snapshot_type)
    let snapshot = match sqlx::query!(
        r#"SELECT snapshot_path, mem_file_path, name, snapshot_type FROM snapshots WHERE id = $1"#,
        snapshot_uuid
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, "Snapshot not found".to_string()).into_response();
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response();
        }
    };

    // Verify snapshot files exist
    if !std::path::Path::new(&snapshot.snapshot_path).exists() {
        return (StatusCode::NOT_FOUND, format!("Snapshot file not found: {}", snapshot.snapshot_path)).into_response();
    }

    // For full VM restore (pause/play), mem_file_path must exist
    let mem_file = match &snapshot.mem_file_path {
        Some(path) => path,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Cannot restore: This is a disk-only snapshot. Use disk restore endpoint instead.".to_string(),
            )
                .into_response();
        }
    };

    if !std::path::Path::new(mem_file).exists() {
        return (StatusCode::NOT_FOUND, format!("Memory file not found: {}", mem_file)).into_response();
    }
    let original_vm = match sqlx::query!(
        r#"SELECT vm_id, ip_address FROM snapshots
           LEFT JOIN vms ON snapshots.vm_id = vms.name
           WHERE snapshots.id = $1"#,
        snapshot_uuid
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(record) => record,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get original VM info: {}", e),
            )
                .into_response();
        }
    };

    let original_vm_id = original_vm.vm_id;

    // Check if original IP is available (original VM must be stopped/deleted)
    let original_ip = original_vm.ip_address.unwrap_or_else(|| {
        // If original VM has no IP in DB, extract from snapshot path
        // This handles case where original VM was deleted
        // We need to store IP in snapshot metadata - for now, fail gracefully
        "unknown".to_string()
    });

    if original_ip == "unknown" || original_ip == "N/A" {
        return (
            StatusCode::BAD_REQUEST,
            "Cannot restore: Original VM's IP not found. The source VM must have been running when snapshot was created.".to_string(),
        )
            .into_response();
    }

    // Check if original VM is still running (would cause IP conflict)
    if state.vms.lock().await.contains_key(&original_vm_id) {
        return (
            StatusCode::CONFLICT,
            format!("Cannot restore: Source VM '{}' is still running. Stop it first to avoid IP conflicts.", original_vm_id),
        )
            .into_response();
    }

    // Check if any running VM has this IP
    let ip_in_use = state.vms.lock().await.values().any(|vm| vm.guest_ip == original_ip);
    if ip_in_use {
        return (
            StatusCode::CONFLICT,
            format!("Cannot restore: IP {} is currently in use by another running VM. Stop the source VM first.", original_ip),
        )
            .into_response();
    }

    // Reuse the original IP and extract octet for IPAM
    let guest_ip = original_ip.clone();
    let gateway_ip = "172.16.0.1";
    let tap_name = new_vm_id.clone(); // Use new VM ID for TAP (host-side name doesn't affect guest)

    let octet: u8 = guest_ip
        .split('.')
        .last()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Mark IP as allocated in IPAM (skip if resuming - IP already allocated)
    if !is_resume {
        let mut ip_lock = state.ipam.lock().await;
        if !ip_lock.try_allocate_specific(octet) {
            return (
                StatusCode::CONFLICT,
                format!("Cannot restore: IP address {} is already allocated.", guest_ip),
            )
                .into_response();
        }
    }

    // Setup Cgroup
    if let Err(e) = cgroups::create_vm_cgroup(&new_vm_id) {
        state.ipam.lock().await.free(octet);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Cgroup Error: {}", e),
        )
            .into_response();
    }

    // Apply resource limits
    if let Err(e) = cgroups::apply_limits(&new_vm_id, 20000, 128 * 1024 * 1024) {
        state.ipam.lock().await.free(octet);
        let _ = cgroups::remove_vm_cgroup(&new_vm_id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Cgroup Limits Error: {}", e),
        )
            .into_response();
    }

    // Create or update DB record (for resume, record already exists)
    let vm_uuid = uuid::Uuid::parse_str(&new_vm_id).unwrap_or_else(|_| uuid::Uuid::new_v4());

    // Try to update first (for resume), then insert if it doesn't exist
    let update_result = sqlx::query!(
        r#"UPDATE vms SET status = 'starting', ip_address = $1, tap_interface = $2 WHERE name = $3"#,
        guest_ip,
        tap_name,
        new_vm_id
    )
    .execute(&state.db)
    .await;

    match update_result {
        Ok(result) if result.rows_affected() == 0 => {
            // Record doesn't exist, insert new one
            if let Err(e) = sqlx::query!(
                r#"
                INSERT INTO vms (id, name, status, ip_address, tap_interface)
                VALUES ($1, $2, 'starting', $3, $4)
                "#,
                vm_uuid,
                new_vm_id,
                guest_ip,
                tap_name
            )
            .execute(&state.db)
            .await
            {
                state.ipam.lock().await.free(octet);
                let _ = cgroups::remove_vm_cgroup(&new_vm_id);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("DB Insert Error: {}", e),
                )
                    .into_response();
            }
        }
        Ok(_) => {
            // Update successful (resume case)
        }
        Err(e) => {
            state.ipam.lock().await.free(octet);
            let _ = cgroups::remove_vm_cgroup(&new_vm_id);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DB Update Error: {}", e),
            )
                .into_response();
        }
    }

    // Setup network
    if let Err(e) = state.network_manager.setup_tap_bridge(&tap_name, "br0").await {
        state.ipam.lock().await.free(octet);
        let _ = cgroups::remove_vm_cgroup(&new_vm_id);
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Network Error: {}", e),
        )
            .into_response();
    }

    // Create VM struct
    let mut vm = MicroVM::new(&new_vm_id, &tap_name, &guest_ip, gateway_ip, octet);
    if let Err(e) = vm.start_process().await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await;
        let _ = cgroups::remove_vm_cgroup(&new_vm_id);
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to start Firecracker: {}", e)).into_response();
    }
    let pid = vm.process.as_ref().and_then(|p| p.id()).ok_or_else(|| anyhow::anyhow!("Failed to get process ID"));
    match pid {
        Ok(pid) => {
            if let Err(e) = cgroups::add_process(&new_vm_id, pid) {
                state.ipam.lock().await.free(octet);
                let _ = vm.cleanup(&state.network_manager).await;
                let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
                    .execute(&state.db)
                    .await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Cgroup Process Jail Error: {}", e),
                )
                    .into_response();
            }
        }
        Err(e) => {
            state.ipam.lock().await.free(octet);
            let _ = vm.cleanup(&state.network_manager).await;
            let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
                .execute(&state.db)
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get process ID: {}", e),
            )
                .into_response();
        }
    }

    // IMPORTANT: Do NOT configure machine-config or network-interfaces before loading a snapshot!
    // Firecracker snapshots already contain those configurations. Configuring them again
    // will cause: "Loading a microVM snapshot not allowed after configuring boot-specific resources."

    // Firecracker snapshots contain the original drive path. We must ensure the disk
    // exists at that EXACT path for portable snapshot restore to work.
    let original_disk_path = format!("{}/rootfs-{}.ext4", INSTANCE_DIR, original_vm_id);

    // Ensure the disk exists at the original path (create if missing for portability)
    if !std::path::Path::new(&original_disk_path).exists() {
        if let Err(e) = prepare_instance_drive(&original_vm_id).await {
            state.ipam.lock().await.free(octet);
            let _ = vm.cleanup(&state.network_manager).await;
            let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
                .execute(&state.db)
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to prepare disk: {}", e),
            )
                .into_response();
        }
    }
    let load_req = SnapshotLoad {
        snapshot_path: snapshot.snapshot_path,
        mem_file_path: mem_file.clone(),
        enable_diff_snapshots: false,
        resume_vm: false,
    };

    match crate::client::send_put_request(&vm.socket_path, "/snapshot/load", &load_req).await {
        Ok(response) => {
            if !response.contains("HTTP/1.1 2") {
                state.ipam.lock().await.free(octet);
                let _ = vm.cleanup(&state.network_manager).await;
                let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
                    .execute(&state.db)
                    .await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to load snapshot: {}", response.lines().next().unwrap_or("Unknown error")),
                )
                    .into_response();
            }
        }
        Err(e) => {
            state.ipam.lock().await.free(octet);
            let _ = vm.cleanup(&state.network_manager).await;
            let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
                .execute(&state.db)
                .await;
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Snapshot load error: {}", e)).into_response();
        }
    }

    let resume_state = VmState {
        state: "Resumed".to_string(),
    };

    match send_patch_request(&vm.socket_path, "/vm", &resume_state).await {
        Ok(response) => {
            if !response.contains("HTTP/1.1 2") {
                state.ipam.lock().await.free(octet);
                let _ = vm.cleanup(&state.network_manager).await;
                let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
                    .execute(&state.db)
                    .await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to resume VM: {}", response.lines().next().unwrap_or("Unknown error")),
                )
                    .into_response();
            }
        }
        Err(e) => {
            state.ipam.lock().await.free(octet);
            let _ = vm.cleanup(&state.network_manager).await;
            let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
                .execute(&state.db)
                .await;
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Resume error: {}", e)).into_response();
        }
    }

    // Update DB status to running and set snapshot lineage (only for user snapshots, not temp)
    let is_user_snapshot = snapshot.snapshot_type == "user";

    if is_user_snapshot {
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'running', created_from_snapshot_id = $1 WHERE name = $2"#,
            snapshot_uuid,
            new_vm_id
        )
        .execute(&state.db)
        .await;
    } else {
        let _ = sqlx::query!(
            r#"UPDATE vms SET status = 'running' WHERE name = $1"#,
            new_vm_id
        )
        .execute(&state.db)
        .await;
    }

    state.vms.lock().await.insert(new_vm_id.clone(), vm);

    // Cleanup temporary pause snapshots after successful resume (only if this was a resume operation)
    if is_resume {
        let cleanup_result = sqlx::query!(
            r#"
            SELECT snapshot_path, mem_file_path
            FROM snapshots
            WHERE vm_id = $1 AND snapshot_type = 'temp'
            "#,
            new_vm_id
        )
        .fetch_all(&state.db)
        .await;

        if let Ok(temp_snapshots) = cleanup_result {
            for snap in temp_snapshots {
                // Delete snapshot files from disk
                if std::path::Path::new(&snap.snapshot_path).exists() {
                    let _ = tokio::fs::remove_file(&snap.snapshot_path).await;
                }
                if let Some(mem_path) = snap.mem_file_path {
                    if std::path::Path::new(&mem_path).exists() {
                        let _ = tokio::fs::remove_file(&mem_path).await;
                    }
                }
            }

            // Delete from database
            let _ = sqlx::query!(
                r#"DELETE FROM snapshots WHERE vm_id = $1 AND snapshot_type = 'temp'"#,
                new_vm_id
            )
            .execute(&state.db)
            .await;

            println!("   ✓ Cleaned up temporary pause snapshots");
        }
    }

    let vm_status = VmStatus {
        id: new_vm_id,
        ip: guest_ip,
        status: "running".to_string(),
        tap: tap_name,
        stats: None,
        // Only include snapshot lineage for user snapshots, not temp snapshots
        created_from_snapshot_id: if is_user_snapshot {
            Some(snapshot_uuid.to_string())
        } else {
            None
        },
        snapshot_name: if is_user_snapshot {
            Some(snapshot.name.unwrap_or_else(|| "Unnamed".to_string()))
        } else {
            None
        },
    };

    (StatusCode::OK, Json(vm_status)).into_response()
}

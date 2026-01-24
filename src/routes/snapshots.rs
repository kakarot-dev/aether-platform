use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::cgroups;
use crate::client::{send_patch_request, send_put_request};
use crate::config::{SnapshotCreate, VmState};
use crate::dtos::{DeleteSnapshotRequest, RestoreRequest, SnapshotInfo, SnapshotListItem, SnapshotRequest, VmStatus};
use crate::{AppState, MicroVM, INSTANCE_DIR, KERNEL_PATH, SNAPSHOTS_DIR};

pub async fn create_snapshot(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SnapshotRequest>,
) -> impl IntoResponse {
    let vm_id = req.vm_id;

    // Get VM from HashMap
    let vms = state.vms.lock().await;
    let vm = match vms.get(&vm_id) {
        Some(vm) => vm,
        None => return (StatusCode::NOT_FOUND, "VM not found".to_string()).into_response(),
    };

    // Check if VM is running or paused
    let current_status = sqlx::query!(
        r#"SELECT status FROM vms WHERE name = $1"#,
        vm_id
    )
    .fetch_optional(&state.db)
    .await;

    let vm_status = match current_status {
        Ok(Some(record)) => {
            if record.status != "running" && record.status != "paused" {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("VM must be running or paused to snapshot (current status: {})", record.status),
                )
                    .into_response();
            }
            record.status
        }
        Ok(None) => return (StatusCode::NOT_FOUND, "VM not found in database".to_string()).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response(),
    };

    // Pause the VM if it's running
    let was_running = vm_status == "running";
    if was_running {
        println!("   Pausing VM before snapshot...");
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
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to pause VM: {}", e),
                )
                    .into_response();
            }
        }

        // Update DB to paused
        if let Err(e) = sqlx::query!(
            r#"UPDATE vms SET status = 'paused' WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await
        {
            eprintln!("⚠️ Warning: Failed to update DB status: {}", e);
        }
    }

    // Create snapshot directory
    let snapshot_dir = format!("{}/{}", SNAPSHOTS_DIR, vm_id);
    if let Err(e) = tokio::fs::create_dir_all(&snapshot_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create snapshot directory: {}", e),
        )
            .into_response();
    }

    // Generate unique snapshot filenames with timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let snap_path = format!("{}/snap_{}", snapshot_dir, timestamp);
    let mem_path = format!("{}/mem_{}", snapshot_dir, timestamp);

    // Send snapshot create request (Full VM snapshot with memory)
    println!("   Creating full VM snapshot (memory + disk)...");
    let snapshot_req = SnapshotCreate {
        snapshot_type: "Full".to_string(),
        snapshot_path: snap_path.clone(),
        mem_file_path: mem_path.clone(),
    };

    match send_put_request(&vm.socket_path, "/snapshot/create", &snapshot_req).await {
        Ok(response) => {
            if !response.contains("HTTP/1.1 2") {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to create snapshot: {}", response.lines().next().unwrap_or("Unknown error")),
                )
                    .into_response();
            }
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create snapshot: {}", e),
            )
                .into_response();
        }
    }

    // Get file sizes
    let snap_size = match tokio::fs::metadata(&snap_path).await {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            eprintln!("⚠️ Warning: Failed to get snapshot file size: {}", e);
            0
        }
    };

    let mem_size = match tokio::fs::metadata(&mem_path).await {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            eprintln!("⚠️ Warning: Failed to get memory file size: {}", e);
            0
        }
    };

    let total_mb = ((snap_size + mem_size) / 1_048_576) as i32;
    println!("   Full snapshot size: {} MB", total_mb);

    // Insert into database (user-created snapshot)
    let snapshot_result = sqlx::query!(
        r#"
        INSERT INTO snapshots (vm_id, name, snapshot_path, mem_file_path, file_size_mb, description, snapshot_type)
        VALUES ($1, $2, $3, $4, $5, $6, 'user')
        RETURNING id, created_at
        "#,
        vm_id,
        req.name,
        snap_path,
        mem_path,
        total_mb,
        req.description
    )
    .fetch_one(&state.db)
    .await;

    let (snapshot_id, created_at) = match snapshot_result {
        Ok(record) => (record.id.to_string(), record.created_at.to_rfc3339()),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save snapshot to database: {}", e),
            )
                .into_response();
        }
    };

    // Resume VM if it was running before
    if was_running {
        println!("   Resuming VM after snapshot...");
        let resume_state = VmState {
            state: "Resumed".to_string(),
        };

        match send_patch_request(&vm.socket_path, "/vm", &resume_state).await {
            Ok(response) => {
                if !response.contains("HTTP/1.1 2") {
                    eprintln!("⚠️ Warning: Failed to resume VM after snapshot");
                } else {
                    // Update DB to running
                    if let Err(e) = sqlx::query!(
                        r#"UPDATE vms SET status = 'running' WHERE name = $1"#,
                        vm_id
                    )
                    .execute(&state.db)
                    .await
                    {
                        eprintln!("⚠️ Warning: Failed to update DB status: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("⚠️ Warning: Failed to resume VM: {}", e);
            }
        }
    }

    println!("✅ Full VM snapshot created successfully (can be used for pause/play): {}", snapshot_id);

    let snapshot_info = SnapshotInfo {
        id: snapshot_id,
        vm_id,
        created_at,
        size_mb: total_mb,
    };

    (StatusCode::OK, Json(snapshot_info)).into_response()
}

pub async fn create_disk_snapshot(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SnapshotRequest>,
) -> impl IntoResponse {
    let vm_id = req.vm_id;

    // Verify VM exists (can be running, paused, or stopped)
    let vm_exists = sqlx::query!(
        r#"SELECT status FROM vms WHERE name = $1"#,
        vm_id
    )
    .fetch_optional(&state.db)
    .await;

    let _vm_status = match vm_exists {
        Ok(Some(record)) => record.status,
        Ok(None) => return (StatusCode::NOT_FOUND, "VM not found in database".to_string()).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response(),
    };

    // Source disk path
    let source_disk = format!("{}/rootfs-{}.ext4", INSTANCE_DIR, vm_id);
    if !std::path::Path::new(&source_disk).exists() {
        return (
            StatusCode::NOT_FOUND,
            format!("VM disk file not found: {}. VM must have run at least once.", source_disk),
        )
            .into_response();
    }

    // Create snapshot directory
    let snapshot_dir = format!("{}/disk-snapshots/{}", SNAPSHOTS_DIR, vm_id);
    if let Err(e) = tokio::fs::create_dir_all(&snapshot_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create snapshot directory: {}", e),
        )
            .into_response();
    }

    // Generate unique snapshot filename with timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let snapshot_disk_path = format!("{}/disk_{}.ext4", snapshot_dir, timestamp);

    // Copy the disk file (this creates our disk snapshot!)
    println!("   Copying disk file to snapshot...");
    if let Err(e) = tokio::fs::copy(&source_disk, &snapshot_disk_path).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to copy disk file: {}", e),
        )
            .into_response();
    }

    // Get file size
    let disk_size = match tokio::fs::metadata(&snapshot_disk_path).await {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            eprintln!("⚠️ Warning: Failed to get snapshot file size: {}", e);
            0
        }
    };

    let size_mb = (disk_size / 1_048_576) as i32;
    println!("   Disk snapshot size: {} MB", size_mb);

    // Insert into database (mem_file_path is NULL for disk-only snapshots, user-created)
    let snapshot_result = sqlx::query!(
        r#"
        INSERT INTO snapshots (vm_id, name, snapshot_path, mem_file_path, file_size_mb, description, snapshot_type)
        VALUES ($1, $2, $3, NULL, $4, $5, 'user')
        RETURNING id, created_at
        "#,
        vm_id,
        req.name,
        snapshot_disk_path,
        size_mb,
        req.description
    )
    .fetch_one(&state.db)
    .await;

    let (snapshot_id, created_at) = match snapshot_result {
        Ok(record) => (record.id.to_string(), record.created_at.to_rfc3339()),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to save snapshot to database: {}", e),
            )
                .into_response();
        }
    };

    println!("✅ Disk snapshot created successfully: {}", snapshot_id);

    let snapshot_info = SnapshotInfo {
        id: snapshot_id,
        vm_id,
        created_at,
        size_mb,
    };

    (StatusCode::OK, Json(snapshot_info)).into_response()
}

pub async fn restore_from_disk_snapshot(
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

    // Check if VM already exists
    if state.vms.lock().await.contains_key(&new_vm_id) {
        return (StatusCode::CONFLICT, "VM with this ID already exists (running)".to_string()).into_response();
    }

    // Check DB too
    let exists_in_db = sqlx::query!(r#"SELECT name FROM vms WHERE name = $1"#, new_vm_id)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(_)) = exists_in_db {
        return (StatusCode::CONFLICT, "VM with this ID already exists in database".to_string()).into_response();
    }

    // Parse snapshot UUID
    let snapshot_uuid = match uuid::Uuid::parse_str(&req.snapshot_id) {
        Ok(uuid) => uuid,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid snapshot ID format".to_string()).into_response(),
    };

    // Fetch snapshot metadata (disk-only snapshots have NULL mem_file_path)
    let snapshot = match sqlx::query!(
        r#"SELECT snapshot_path, mem_file_path as "mem_file_path?", name FROM snapshots WHERE id = $1"#,
        snapshot_uuid
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::NOT_FOUND, "Snapshot not found".to_string()).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response(),
    };

    // Verify this is a disk-only snapshot
    if snapshot.mem_file_path.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            "This is a full VM snapshot (pause/play), not a disk snapshot. Use /api/vms/restore instead.".to_string(),
        )
            .into_response();
    }

    // Verify snapshot disk exists
    if !std::path::Path::new(&snapshot.snapshot_path).exists() {
        return (StatusCode::NOT_FOUND, format!("Snapshot disk file not found: {}", snapshot.snapshot_path)).into_response();
    }

    println!("   Disk snapshot verified");

    // Allocate new IP (fresh VM, fresh IP)
    let octet = {
        let mut ip_lock = state.ipam.lock().await;
        match ip_lock.allocate() {
            Some(i) => i,
            None => return (StatusCode::SERVICE_UNAVAILABLE, "Subnet Full".to_string()).into_response(),
        }
    };
    let guest_ip = format!("172.16.0.{}", octet);
    let gateway_ip = "172.16.0.1";
    let tap_name = new_vm_id.clone();

    println!("   Allocated new IP: {}", guest_ip);

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

    // Create DB record
    let vm_uuid = uuid::Uuid::parse_str(&new_vm_id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO vms (id, name, status, ip_address, tap_interface, created_from_snapshot_id)
        VALUES ($1, $2, 'starting', $3, $4, $5)
        "#,
        vm_uuid,
        new_vm_id,
        guest_ip,
        tap_name,
        snapshot_uuid
    )
    .execute(&state.db)
    .await
    {
        state.ipam.lock().await.free(octet);
        let _ = cgroups::remove_vm_cgroup(&new_vm_id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB Error: {}", e),
        )
            .into_response();
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

    // Copy snapshot disk to new VM's disk location
    let new_disk_path = format!("{}/rootfs-{}.ext4", INSTANCE_DIR, new_vm_id);
    println!("   Copying snapshot disk to: {}", new_disk_path);

    if let Err(e) = tokio::fs::copy(&snapshot.snapshot_path, &new_disk_path).await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await;
        let _ = cgroups::remove_vm_cgroup(&new_vm_id);
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to copy snapshot disk: {}", e),
        )
            .into_response();
    }

    // Now boot a fresh VM with this disk (same as deploy_vm)
    let mut vm = MicroVM::new(&new_vm_id, &tap_name, &guest_ip, gateway_ip, octet);

    // Spawn Firecracker process
    if let Err(e) = vm.start_process().await {
        state.ipam.lock().await.free(octet);
        let _ = state.network_manager.teardown_tap(&tap_name).await;
        let _ = cgroups::remove_vm_cgroup(&new_vm_id);
        let _ = tokio::fs::remove_file(&new_disk_path).await;
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to start Firecracker: {}", e)).into_response();
    }

    // Move process to cgroup
    let pid = vm.process.as_ref().and_then(|p| p.id()).ok_or_else(|| anyhow::anyhow!("Failed to get process ID"));
    if let Ok(pid) = pid {
        if let Err(e) = cgroups::add_process(&new_vm_id, pid) {
            state.ipam.lock().await.free(octet);
            let _ = vm.cleanup(&state.network_manager).await;
            let _ = tokio::fs::remove_file(&new_disk_path).await;
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

    // Configure VM resources
    if let Err(e) = vm.configure_vm().await {
        state.ipam.lock().await.free(octet);
        let _ = vm.cleanup(&state.network_manager).await;
        let _ = tokio::fs::remove_file(&new_disk_path).await;
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Set boot source with NEW IP
    if let Err(e) = vm.set_boot_source(KERNEL_PATH).await {
        state.ipam.lock().await.free(octet);
        let _ = vm.cleanup(&state.network_manager).await;
        let _ = tokio::fs::remove_file(&new_disk_path).await;
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Boot Source Error: {}", e),
        )
            .into_response();
    }

    // Attach the restored disk
    if let Err(e) = vm.attach_rootfs(&new_disk_path).await {
        state.ipam.lock().await.free(octet);
        let _ = vm.cleanup(&state.network_manager).await;
        let _ = tokio::fs::remove_file(&new_disk_path).await;
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("RootFS Error: {}", e),
        )
            .into_response();
    }

    // Attach network
    if let Err(e) = vm.attach_network().await {
        state.ipam.lock().await.free(octet);
        let _ = vm.cleanup(&state.network_manager).await;
        let _ = tokio::fs::remove_file(&new_disk_path).await;
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Net Attach Error: {}", e),
        )
            .into_response();
    }

    // Start the VM
    if let Err(e) = vm.start_instance().await {
        state.ipam.lock().await.free(octet);
        let _ = vm.cleanup(&state.network_manager).await;
        let _ = tokio::fs::remove_file(&new_disk_path).await;
        let _ = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, new_vm_id)
            .execute(&state.db)
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Start Error: {}", e),
        )
            .into_response();
    }

    // Update DB status to running
    if let Err(e) = sqlx::query!(
        r#"UPDATE vms SET status = 'running' WHERE name = $1"#,
        new_vm_id
    )
    .execute(&state.db)
    .await
    {
        eprintln!("⚠️ Warning: Failed to update DB status: {}", e);
    }

    // Store in HashMap
    state.vms.lock().await.insert(new_vm_id.clone(), vm);

    println!("✅ VM restored from disk snapshot successfully");

    let vm_status = VmStatus {
        id: new_vm_id,
        ip: guest_ip,
        status: "running".to_string(),
        tap: tap_name,
        stats: None,
        created_from_snapshot_id: Some(snapshot_uuid.to_string()),
        snapshot_name: Some(snapshot.name.unwrap_or_else(|| "Unnamed".to_string())),
    };

    (StatusCode::OK, Json(vm_status)).into_response()
}

pub async fn delete_snapshot(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeleteSnapshotRequest>,
) -> impl IntoResponse {
    println!("🗑️  Received Delete Snapshot Request for: {}", req.snapshot_id);

    // Parse snapshot UUID
    let snapshot_uuid = match uuid::Uuid::parse_str(&req.snapshot_id) {
        Ok(uuid) => uuid,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid snapshot ID format".to_string()).into_response(),
    };

    // Fetch snapshot file paths before deleting from DB
    let snapshot = match sqlx::query!(
        r#"SELECT snapshot_path, mem_file_path as "mem_file_path?" FROM snapshots WHERE id = $1"#,
        snapshot_uuid
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::NOT_FOUND, "Snapshot not found".to_string()).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response(),
    };

    // Delete from database first
    let result = sqlx::query!(r#"DELETE FROM snapshots WHERE id = $1"#, snapshot_uuid)
        .execute(&state.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                // Delete snapshot files from disk
                println!("   Deleting snapshot files from disk...");

                if std::path::Path::new(&snapshot.snapshot_path).exists() {
                    if let Err(e) = tokio::fs::remove_file(&snapshot.snapshot_path).await {
                        eprintln!("⚠️ Warning: Failed to delete snapshot file: {}", e);
                    }
                }

                if let Some(mem_path) = snapshot.mem_file_path {
                    if std::path::Path::new(&mem_path).exists() {
                        if let Err(e) = tokio::fs::remove_file(&mem_path).await {
                            eprintln!("⚠️ Warning: Failed to delete memory file: {}", e);
                        }
                    }
                }

                println!("✅ Snapshot deleted successfully");

                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "status": "deleted", "id": req.snapshot_id })),
                )
                    .into_response()
            } else {
                (StatusCode::NOT_FOUND, "Snapshot not found".to_string()).into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response(),
    }
}

pub async fn list_snapshots(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snapshots = sqlx::query!(
        r#"
        SELECT s.id, s.vm_id, s.name, s.created_at, s.file_size_mb, s.description,
               v.status as "source_vm_status?"
        FROM snapshots s
        LEFT JOIN vms v ON s.vm_id = v.name
        WHERE s.snapshot_type = 'user'
        ORDER BY s.created_at DESC
        "#
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let snapshot_list: Vec<SnapshotListItem> = snapshots
        .into_iter()
        .map(|row| SnapshotListItem {
            id: row.id.to_string(),
            vm_id: row.vm_id,
            name: row.name.unwrap_or_else(|| "Unnamed".to_string()),
            created_at: row.created_at.to_rfc3339(),
            size_mb: row.file_size_mb.unwrap_or(0),
            description: row.description,
            source_vm_status: row.source_vm_status,
        })
        .collect();

    (StatusCode::OK, Json(snapshot_list)).into_response()
}

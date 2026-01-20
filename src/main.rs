use crate::client::{send_patch_request, send_put_request};
use crate::config::{Action, BootSource, Drive, MachineConfiguration, NetworkInterface, SnapshotCreate, SnapshotLoad, VmState};
use crate::dtos::{DeleteSnapshotRequest, DeleteVmRequest, DeployVmRequest, RestoreRequest, SnapshotInfo, SnapshotListItem, SnapshotRequest, StopVmRequest, SystemInfo, VmIdRequest, VmStatus};
use crate::ipam::IpAllocator;
use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Mutex;
use tower_http::services::ServeDir;

mod cgroups;
mod client;
mod config;
mod dtos;
mod firewall;
mod ipam;
mod network;

const KERNEL_PATH: &str = "/home/axel/aether-platform/resources/vmlinux.bin";
const ROOTFS_PATH: &str = "/home/axel/aether-platform/resources/aether-base.ext4";
const INSTANCE_DIR: &str = "/tmp/aether-instances";
const SNAPSHOTS_DIR: &str = "/home/axel/aether-platform/resources/snapshots";

struct AppState {
    vms: Mutex<HashMap<String, MicroVM>>,
    ipam: Mutex<IpAllocator>,
    db: PgPool,
    network_manager: network::NetworkManager,
}
// The Hypervisor manages the lifecycle of a single Firecracker process.
struct MicroVM {
    id: String,
    socket_path: PathBuf,
    // We hold the child process to ensure it doesn't become a zombie.
    process: Option<tokio::process::Child>,
    tap_name: String,
    guest_ip: String,
    gateway_ip: String,
    ip_octet: u8,
}

impl MicroVM {
    /// Creates a new MicroVM struct (does not start the process yet)
    fn new(id: &str, tap_name: &str, ip_addr: &str, gateway: &str, ip_octet: u8) -> Self {
        let socket_path = PathBuf::from(format!("/tmp/firecracker_{}.socket", id));

        Self {
            id: id.to_string(),
            socket_path,
            process: None,
            tap_name: tap_name.to_string(),
            guest_ip: ip_addr.to_string(),
            gateway_ip: gateway.to_string(),
            ip_octet,
        }
    }
    /// Spawns the Firecracker process in the background.
    /// This is the "Systems" part: manipulating Linux processes.
    async fn start_process(&mut self) -> Result<()> {
        // cleanup old socket if it exists (Firecracker will fail otherwise)
        if self.socket_path.exists() {
            tokio::fs::remove_file(&self.socket_path)
                .await
                .context("Failed to remove old socket")?;
        }

        println!("🚀 Spawning Firecracker process for VM: {}", self.id);

        // Create log files for VM serial console output
        let log_dir = PathBuf::from("/tmp/aether-logs");
        std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

        let stdout_log = log_dir.join(format!("{}-console.log", self.id));
        let stderr_log = log_dir.join(format!("{}-error.log", self.id));

        let stdout_file = File::create(&stdout_log).context("Failed to create stdout log file")?;
        let stderr_file = File::create(&stderr_log).context("Failed to create stderr log file")?;

        println!("📝 Serial console will be logged to: {:?}", stdout_log);

        // Command to run firecracker with serial console redirected to log files
        // Redirect stdin to null to detach from terminal and prevent signal interference
        let child = Command::new("firecracker")
            .arg("--api-sock")
            .arg(&self.socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .context("Failed to spawn firecracker binary")?;

        self.process = Some(child);

        // Wait for the socket to be created (poll for up to 5 seconds)
        println!("⏳ Waiting for Firecracker socket to be ready...");
        for _ in 0..50 {
            if self.socket_path.exists() {
                println!("✅ Socket is ready!");
                return Ok(());
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        anyhow::bail!("Firecracker socket was not created within timeout")
    }
    // Configures the virtual machine allowing users to set limitations on resources
    async fn configure_vm(&self) -> Result<()> {
        println!("🧠 Configuring VM via Raw HTTP over Unix Socket...");

        let machine_config = MachineConfiguration {
            vcpu_count: 1,
            mem_size_mib: 128,
            smt: Some(false),
        };
        // Send the PUT request to configure the machine
        let response = send_put_request(&self.socket_path, "/machine-config", &machine_config)
            .await
            .context("Failed to send machine config request")?;

        // Check if response contains HTTP 2xx status
        if !response.contains("HTTP/1.1 2") {
            anyhow::bail!(
                "Failed to configure VM: {}",
                response.lines().next().unwrap_or("Unknown error")
            );
        }

        Ok(())
    }

    async fn set_boot_source(&self, kernel_path: &str) -> Result<()> {
        println!("💿 Setting Boot Source...");

        let boot_source = BootSource {
            kernel_image_path: kernel_path.to_string(),
            // console=ttyS0: Redirects output to the terminal so we can see it.
            // reboot=k: Allows the kernel to reboot the VM.
            // panic=1: Reboot immediately on panic.
            boot_args: Some(format!(
                "console=ttyS0 reboot=k panic=1 pci=off ip={}::{}:255.255.255.0::eth0:off",
                &self.guest_ip, &self.gateway_ip
            )),
        };

        // Send the PUT request to configure the machine
        let response = send_put_request(&self.socket_path, "/boot-source", &boot_source)
            .await
            .context("Failed to send machine config request")?;

        // Check if response contains HTTP 2xx status
        if !response.contains("HTTP/1.1 2") {
            anyhow::bail!(
                "Failed to configure VM: {}",
                response.lines().next().unwrap_or("Unknown error")
            );
        }
        Ok(())
    }

    async fn attach_rootfs(&self, fs_path: &str) -> Result<()> {
        println!("💾 Attaching Root Filesystem...");

        let drive = Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: fs_path.to_string(),
            is_root_device: true,
            is_read_only: false,
        };

        // Send the PUT request to configure the machine
        let response = send_put_request(&self.socket_path, "/drives/rootfs", &drive)
            .await
            .context("Failed to send machine config request")?;

        // Check if response contains HTTP 2xx status
        if !response.contains("HTTP/1.1 2") {
            anyhow::bail!(
                "Failed to configure VM: {}",
                response.lines().next().unwrap_or("Unknown error")
            );
        }
        Ok(())
    }

    async fn start_instance(&self) -> Result<()> {
        println!("🔋 Starting Instance...");

        let action = Action {
            action_type: "InstanceStart".to_string(),
        };

        // Send the PUT request to configure the machine
        let response = send_put_request(&self.socket_path, "/actions", &action)
            .await
            .context("Failed to send machine config request")?;

        // Check if response contains HTTP 2xx status
        if !response.contains("HTTP/1.1 2") {
            anyhow::bail!(
                "Failed to configure VM: {}",
                response.lines().next().unwrap_or("Unknown error")
            );
        }
        Ok(())
    }

    async fn attach_network(&self) -> Result<()> {
        println!("🌐 Attaching Network Interface...");
        let net_iface = NetworkInterface {
            iface_id: "eth0".to_string(),
            host_dev_name: self.tap_name.clone(),
        };
        let response = send_put_request(&self.socket_path, "/network-interfaces/eth0", &net_iface)
            .await
            .context("Failed to send network interface request")?;
        if !response.contains("HTTP/1.1 2") {
            anyhow::bail!(
                "Failed to configure VM: {}",
                response.lines().next().unwrap_or("Unknown error")
            );
        }
        Ok(())
    }

    // Cleanup only the running process, cgroups, and network - preserve disk for resume
    pub async fn cleanup_process_only(&mut self, net_mgr: &network::NetworkManager) -> Result<()> {
        println!("⏸️  Pausing VM process: {}", self.id);
        if let Some(mut child) = self.process.take() {
            println!("   -> Killing Firecracker process...");
            let _ = child.kill().await;
        }

        // Remove cgroup
        println!("   -> Removing Cgroup...");
        if let Err(e) = cgroups::remove_vm_cgroup(&self.id) {
            eprintln!("   ⚠️ Warning: Failed to remove cgroup: {}", e);
        }

        // Remove persistent TAP device using native netlink
        println!("   -> Removing Network Interface {}...", self.tap_name);
        if let Err(e) = net_mgr.teardown_tap(&self.tap_name).await {
            eprintln!("   ⚠️ Warning: Failed to remove TAP device: {}", e);
        }

        // Delete Firecracker socket file
        if self.socket_path.exists() {
            println!("   -> Deleting Socket File...");
            if let Err(e) = fs::remove_file(&self.socket_path).await {
                eprintln!("   ⚠️ Warning: Failed to remove socket file: {}", e);
            }
        }

        // NOTE: Disk image and logs are preserved for resume from snapshot

        Ok(())
    }

    // Full cleanup - deletes everything including disk
    pub async fn cleanup(&mut self, net_mgr: &network::NetworkManager) -> Result<()> {
        println!("💀 Stopping VM: {}", self.id);
        if let Some(mut child) = self.process.take() {
            println!("   -> Killing Firecracker process...");
            let _ = child.kill().await;
        }

        // Remove cgroup
        println!("   -> Removing Cgroup...");
        if let Err(e) = cgroups::remove_vm_cgroup(&self.id) {
            eprintln!("   ⚠️ Warning: Failed to remove cgroup: {}", e);
        }

        // Remove persistent TAP device using native netlink
        println!("   -> Removing Network Interface {}...", self.tap_name);
        if let Err(e) = net_mgr.teardown_tap(&self.tap_name).await {
            eprintln!("   ⚠️ Warning: Failed to remove TAP device: {}", e);
        }

        // Delete Firecracker socket file
        if self.socket_path.exists() {
            println!("   -> Deleting Socket File...");
            if let Err(e) = fs::remove_file(&self.socket_path).await {
                eprintln!("   ⚠️ Warning: Failed to remove socket file: {}", e);
            }
        }

        // Delete disk image
        let drive_path = format!("/tmp/aether-instances/rootfs-{}.ext4", self.id);
        if std::path::Path::new(&drive_path).exists() {
            println!("   -> Deleting Disk Image...");
            let _ = fs::remove_file(&drive_path).await;
        }

        // Delete log files
        let console_log = format!("/tmp/aether-logs/{}-console.log", self.id);
        let error_log = format!("/tmp/aether-logs/{}-error.log", self.id);

        if std::path::Path::new(&console_log).exists() {
            println!("   -> Deleting Console Log...");
            let _ = fs::remove_file(&console_log).await;
        }

        if std::path::Path::new(&error_log).exists() {
            println!("   -> Deleting Error Log...");
            let _ = fs::remove_file(&error_log).await;
        }

        Ok(())
    }
}

async fn prepare_instance_drive(vm_id: &str) -> Result<String> {
    use tokio::fs;

    // Ensure instance directory exists
    if let Err(e) = fs::create_dir_all(INSTANCE_DIR).await {
        anyhow::bail!(
            "Failed to create instance directory {}: {}",
            INSTANCE_DIR,
            e
        );
    }

    let dest_path = format!("{}/rootfs-{}.ext4", INSTANCE_DIR, vm_id);

    // THE CLONE: We copy the clean base image to a unique file for this VM
    // Warning: This takes time (disk I/O). 300MB takes a few seconds.
    println!("💿 Cloning filesystem for VM {}...", vm_id);

    if let Err(e) = fs::copy(ROOTFS_PATH, &dest_path).await {
        anyhow::bail!(
            "Failed to copy rootfs from {} to {}: {}",
            ROOTFS_PATH,
            dest_path,
            e
        );
    }

    println!("✅ Rootfs ready at: {}", dest_path);
    Ok(dest_path)
}
async fn deploy_vm(
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

async fn stop_vm(
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

async fn delete_vm(
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

async fn list_vms(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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

async fn system_info() -> impl IntoResponse {
    // Get host IP address by reading network interfaces
    let host_ip = std::process::Command::new("sh")
        .arg("-c")
        .arg("ip route get 1 | awk '{print $7; exit}'")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "N/A".to_string());

    // Get primary interface name
    let interface = std::process::Command::new("sh")
        .arg("-c")
        .arg("ip route get 1 | awk '{print $5; exit}'")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "eth0".to_string());

    let info = SystemInfo {
        host_ip,
        bridge_ip: "172.16.0.1".to_string(),
        vm_subnet: "172.16.0.0/24".to_string(),
        interface,
    };

    (StatusCode::OK, Json(info)).into_response()
}

async fn pause_vm(
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

                if let Ok(_) = send_put_request(&vm.socket_path, "/snapshot/create", &snapshot_req).await {
                    let snap_size = tokio::fs::metadata(&snap_path).await.map(|m| m.len()).unwrap_or(0);
                    let mem_size = tokio::fs::metadata(&mem_path).await.map(|m| m.len()).unwrap_or(0);
                    let total_size_mb = ((snap_size + mem_size) / 1_048_576) as i32;

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
                        snap_path,
                        mem_path,
                        total_size_mb
                    )
                    .execute(&state.db)
                    .await;
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

async fn resume_vm(
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

async fn create_snapshot(
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

async fn restore_vm(
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

    match send_put_request(&vm.socket_path, "/snapshot/load", &load_req).await {
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

async fn create_disk_snapshot(
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

async fn restore_from_disk_snapshot(
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

async fn delete_snapshot(
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

async fn list_snapshots(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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

#[tokio::main]
async fn main() -> Result<()> {
    // Raise capabilities once at the start for all network operations
    network::NetworkManager::raise_ambient_cap_net_admin()?;

    // Initialize cgroups (requires root)
    if let Err(e) = cgroups::initialize() {
        eprintln!("⚠️ Failed to initialize cgroups: {}. Run as Root!", e);
        anyhow::bail!("Cgroups initialization failed");
    }
    println!("✅ Cgroups initialized");

    // Initialize native network manager
    let net_mgr = network::NetworkManager::new()
        .await
        .context("Failed to initialize NetworkManager")?;

    println!("✅ Native NetworkManager initialized");

    // Initialize firewall manager
    let firewall_mgr =
        firewall::FirewallManager::new().context("Failed to initialize FirewallManager")?;

    // Enable IP forwarding for VM routing
    firewall_mgr
        .enable_ip_forwarding()
        .context("Failed to enable IP forwarding")?;

    // Setup NAT rules for VM subnet
    firewall_mgr
        .setup_nat("br0", "172.16.0.0/24")
        .context("Failed to setup NAT rules")?;

    // Keep firewall_mgr in scope - it will cleanup NAT rules via Drop when program exits
    let _firewall_mgr = firewall_mgr;

    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Connect to PostgreSQL database
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to Postgres");

    // Run database migrations
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    println!("✅ Persistence Layer Active: Connected to Postgres.");

    // Startup reconciliation: Mark orphaned VMs as 'crashed' and free IPs
    let orphaned_count = sqlx::query!(
        r#"
        UPDATE vms
        SET status = 'crashed', ip_address = NULL
        WHERE status IN ('starting', 'running')
        "#
    )
    .execute(&pool)
    .await
    .map(|result| result.rows_affected())
    .unwrap_or(0);

    if orphaned_count > 0 {
        println!(
            "🔄 Marked {} orphaned VM(s) as crashed and freed their IPs",
            orphaned_count
        );
    }

    // Delete stopped and crashed VMs (they can't be recovered)
    let deleted_count = sqlx::query!(
        r#"DELETE FROM vms WHERE status IN ('stopped', 'crashed')"#
    )
    .execute(&pool)
    .await
    .map(|result| result.rows_affected())
    .unwrap_or(0);

    if deleted_count > 0 {
        println!(
            "🗑️  Deleted {} stopped/crashed VM(s) from database",
            deleted_count
        );
    }

    let shared_state = Arc::new(AppState {
        vms: Mutex::new(HashMap::new()),
        ipam: Mutex::new(IpAllocator::new()),
        db: pool,
        network_manager: net_mgr,
    });

    let app = Router::new()
        .route("/api/deploy", post(deploy_vm))
        .route("/api/stop", post(stop_vm))
        .route("/api/delete", post(delete_vm))
        .route("/api/vms", get(list_vms))
        .route("/api/system", get(system_info))
        .route("/api/health", get(|| async { "Aether is running" }))
        .route("/api/vms/pause", post(pause_vm))
        .route("/api/vms/resume", post(resume_vm))
        .route("/api/vms/snapshot", post(create_snapshot))  // Full VM snapshot (pause/play)
        .route("/api/vms/restore", post(restore_vm))        // Restore full VM snapshot
        .route("/api/vms/disk-snapshot", post(create_disk_snapshot))  // Disk-only snapshot
        .route("/api/vms/restore-disk", post(restore_from_disk_snapshot))  // Restore from disk snapshot
        .route("/api/snapshots", get(list_snapshots))
        .route("/api/snapshots/delete", post(delete_snapshot))
        .fallback_service(ServeDir::new("static"))
        .with_state(shared_state.clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("🛸 Aether Control Plane listening on port 3000...");
    println!("📊 Dashboard available at http://localhost:3000");
    println!("   Press Ctrl+C to stop all VMs and exit gracefully");

    // Spawn the server in a separate task so we can handle Ctrl+C
    let server_handle = tokio::spawn(async move { axum::serve(listener, app).await });

    // Wait for Ctrl+C signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\n🛑 Shutting down gracefully...");

            // When Ctrl+C is pressed, Firecracker child processes also receive the signal and terminate
            // No need to try pausing/snapshotting - just clean up and update database state

            let mut vms = shared_state.vms.lock().await;
            let vm_ids: Vec<String> = vms.keys().cloned().collect();

            if !vm_ids.is_empty() {
                // Clean up network interfaces and processes
                let mut cleanup_tasks = vec![];
                let net_mgr = &shared_state.network_manager;

                for vm_id in &vm_ids {
                    if let Some(mut vm) = vms.remove(vm_id) {
                        cleanup_tasks.push(async move {
                            // Cleanup network only (Firecracker process already dead, preserve disk)
                            let _ = vm.cleanup_process_only(net_mgr).await;
                            vm.id.clone()
                        });
                    }
                }
                drop(vms);

                futures::future::join_all(cleanup_tasks).await;

                // Mark all running VMs as stopped in database (Firecracker is gone)
                for vm_id in vm_ids {
                    let _ = sqlx::query!(
                        r#"UPDATE vms SET status = 'stopped' WHERE name = $1 AND status = 'running'"#,
                        vm_id
                    )
                    .execute(&shared_state.db)
                    .await;
                }
            }

            // Paused VMs remain paused (they have temp snapshots from manual pause)
            println!("   All VMs stopped. Use RESUME to restart paused VMs.");

            println!("💀 System Shutdown Complete.");
            Ok(())
        }
        result = server_handle => {
            result.context("Server task panicked")??;
            Ok(())
        }
    }
}

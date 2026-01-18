use crate::client::send_put_request;
use crate::config::{Action, BootSource, Drive, MachineConfiguration, NetworkInterface};
use crate::dtos::{DeleteVmRequest, DeployVmRequest, StopVmRequest, SystemInfo, VmStatus};
use crate::ipam::IpAllocator;
use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::services::ServeDir;
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
    let pid = vm.process.as_ref().and_then(|p| p.id()).ok_or_else(|| {
        anyhow::anyhow!("Failed to get process ID")
    });

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
    println!("🛑 Received Stop Request for: {}", vm_id);

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

            // Update DB Record (Mark as 'stopped' and clear IP)
            let _ = sqlx::query!(
                r#"UPDATE vms SET status = 'stopped', ip_address = NULL WHERE name = $1"#,
                vm_id
            )
            .execute(&state.db)
            .await;

            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "stopped", "id": vm_id })),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "VM Not Found").into_response(),
    }
}

async fn delete_vm(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeleteVmRequest>,
) -> impl IntoResponse {
    let vm_id = payload.vm_id;
    println!("🗑️  Received Delete Request for: {}", vm_id);

    // Delete from database
    let result = sqlx::query!(r#"DELETE FROM vms WHERE name = $1"#, vm_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
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
    // Query database for all VMs
    let rows = sqlx::query!(
        r#"
        SELECT id, name, status, ip_address, tap_interface
        FROM vms
        ORDER BY created_at DESC
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
            println!("\n🛑 Received Ctrl+C, shutting down gracefully...");

            // Clean up all VMs
            let mut vms = shared_state.vms.lock().await;
            let vm_ids: Vec<String> = vms.keys().cloned().collect();

            if vm_ids.is_empty() {
                println!("   No VMs to clean up");
            } else {
                println!("   Cleaning up {} VM(s)...", vm_ids.len());

                // Collect all cleanup tasks
                let mut cleanup_tasks = vec![];
                let net_mgr = &shared_state.network_manager;

                for vm_id in vm_ids {
                    if let Some(mut vm) = vms.remove(&vm_id) {
                        cleanup_tasks.push(async move {
                            let id = vm.id.clone();
                            let octet = vm.ip_octet;
                            let result = vm.cleanup(net_mgr).await;
                            (id, octet, result)
                        });
                    }
                }
                drop(vms); // Release lock before awaiting

                // Execute all cleanups in parallel
                let results = futures::future::join_all(cleanup_tasks).await;

                // Report results and free IPs
                for (vm_id, octet, result) in results {
                    match result {
                        Ok(_) => {
                            println!("   -> Stopped VM: {} ✅", vm_id);
                            // Mark as stopped in DB and clear IP
                            let _ = sqlx::query!(
                                r#"UPDATE vms SET status = 'stopped', ip_address = NULL WHERE name = $1"#,
                                vm_id
                            )
                            .execute(&shared_state.db)
                            .await;
                        }
                        Err(e) => {
                            println!("   -> Stopped VM: {} ❌ Error: {}", vm_id, e);
                            // Mark as failed in DB and clear IP
                            let _ = sqlx::query!(
                                r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
                                vm_id
                            )
                            .execute(&shared_state.db)
                            .await;
                        }
                    }
                    shared_state.ipam.lock().await.free(octet);
                }
            }

            println!("💀 System Shutdown Complete.");
            Ok(())
        }
        result = server_handle => {
            result.context("Server task panicked")??;
            Ok(())
        }
    }
}

use crate::client::send_put_request;
use crate::config::{Action, BootSource, Drive, MachineConfiguration, NetworkInterface};
use crate::dtos::{DeployVmRequest, StopVmRequest};
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

mod client;
mod config;
mod dtos;
mod ipam;
mod network;

const KERNEL_PATH: &str = "/home/axel/aether-platform/resources/vmlinux.bin";
const ROOTFS_PATH: &str = "/home/axel/aether-platform/resources/bionic.rootfs.ext4";
const INSTANCE_DIR: &str = "/tmp/aether-instances";

struct AppState {
    vms: Mutex<HashMap<String, MicroVM>>,
    ipam: Mutex<IpAllocator>,
    db: PgPool,
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

    pub async fn cleanup(&mut self) -> Result<()> {
        println!("💀 Stopping VM: {}", self.id);
        if let Some(mut child) = self.process.take() {
            println!("   -> Killing Firecracker process...");
            let _ = child.kill().await;
        }

        // Raise capabilities for network operations
        println!("   -> Removing Network Interface {}...", self.tap_name);
        if let Err(e) = network::NetworkManager::raise_ambient_cap_net_admin() {
            eprintln!("   ⚠️ Warning: Failed to raise capabilities for TAP cleanup: {}", e);
        }
        if let Err(e) = network::NetworkManager::teardown_tap(&self.tap_name) {
            eprintln!("   ⚠️ Warning: Failed to remove TAP device: {}", e);
        }

        let drive_path = format!("/tmp/aether-instances/rootfs-{}.ext4", self.id);
        if std::path::Path::new(&drive_path).exists() {
            println!("   -> Deleting Disk Image...");
            let _ = fs::remove_file(&drive_path).await;
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
    // Assign Ip
    let octet = {
        let mut ip_lock = state.ipam.lock().await;
        match ip_lock.allocate() {
            Some(i) => i,
            None => return (StatusCode::SERVICE_UNAVAILABLE, "Subnet Full").into_response(),
        }
    };
    // Raise capabilities for this handler context
    if let Err(e) = network::NetworkManager::raise_ambient_cap_net_admin() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to raise capabilities: {}", e),
        )
            .into_response();
    }
    let guest_ip = format!("172.16.0.{}", octet);
    let gateway_ip = "172.16.0.1";
    let vm_id = payload.vm_id.clone();
    let tap_name = format!("tap-{}", vm_id);

    println!("🛸 Deploying VM with ID: {} and IP: {}", vm_id, guest_ip);

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
    // 1. Host Network Plumbing (Sudo/Cap required)
    if let Err(e) = network::NetworkManager::setup_tap_bridge(&tap_name, "br0").await {
        // Mark as failed in DB and free IP
        println!("❌ Deployment failed at network setup, marking as 'failed' in DB");
        state.ipam.lock().await.free(octet);
        if let Err(db_err) = sqlx::query!(
            r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#,
            vm_id
        )
        .execute(&state.db)
        .await {
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
        let _ = sqlx::query!(r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#, vm_id).execute(&state.db).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // 4. Configure Resources (CPU/RAM)
    if let Err(e) = vm.configure_vm().await {
        state.ipam.lock().await.free(octet);
        let _ = sqlx::query!(r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#, vm_id).execute(&state.db).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // 5. The Sequence You Asked About (Yes, it goes here!)
    // We await each step. If one fails, we return Error immediately.

    // Set Boot Source
    if let Err(e) = vm.set_boot_source(KERNEL_PATH).await {
        state.ipam.lock().await.free(octet);
        let _ = sqlx::query!(r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#, vm_id).execute(&state.db).await;
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
            let _ = sqlx::query!(r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#, vm_id).execute(&state.db).await;
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
        let _ = sqlx::query!(r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#, vm_id).execute(&state.db).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("RootFS Error: {}", e),
        )
            .into_response();
    }

    // Attach Network (Guest Side)
    if let Err(e) = vm.attach_network().await {
        state.ipam.lock().await.free(octet);
        let _ = sqlx::query!(r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#, vm_id).execute(&state.db).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Net Attach Error: {}", e),
        )
            .into_response();
    }

    // 6. Ignite
    if let Err(e) = vm.start_instance().await {
        state.ipam.lock().await.free(octet);
        let _ = sqlx::query!(r#"UPDATE vms SET status = 'failed', ip_address = NULL WHERE name = $1"#, vm_id).execute(&state.db).await;
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
        let _ = network::NetworkManager::teardown_tap(&tap_name);

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
            if let Err(e) = vm.cleanup().await {
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
#[tokio::main]
async fn main() -> Result<()> {
    // Raise capabilities once at the start for all network operations
    network::NetworkManager::raise_ambient_cap_net_admin()?;

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
    sqlx::migrate!().run(&pool).await.expect("Failed to run migrations");

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
        println!("🔄 Marked {} orphaned VM(s) as crashed and freed their IPs", orphaned_count);
    }

    let shared_state = Arc::new(AppState {
        vms: Mutex::new(HashMap::new()),
        ipam: Mutex::new(IpAllocator::new()),
        db: pool,
    });

    let app = Router::new()
        .route("/deploy", post(deploy_vm))
        .route("/stop", post(stop_vm))
        .route("/health", get(|| async { "Aether is running" }))
        .with_state(shared_state.clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("🛸 Aether Control Plane listening on port 3000...");
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
                for vm_id in vm_ids {
                    if let Some(mut vm) = vms.remove(&vm_id) {
                        cleanup_tasks.push(async move {
                            let id = vm.id.clone();
                            let octet = vm.ip_octet;
                            let result = vm.cleanup().await;
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

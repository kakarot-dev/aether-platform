use crate::client::send_put_request;
use crate::config::{Action, BootSource, Drive, MachineConfiguration, NetworkInterface};
use crate::dtos::DeployVmRequest;
use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Mutex;

mod client;
mod config;
mod dtos;
mod network;

const KERNEL_PATH: &str = "/home/axel/aether-platform/resources/vmlinux.bin";
const ROOTFS_PATH: &str = "/home/axel/aether-platform/resources/bionic.rootfs.ext4";
const INSTANCE_DIR: &str = "/tmp/aether-instances";

struct AppState {
    vms: Mutex<HashMap<String, MicroVM>>,
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
}

impl MicroVM {
    /// Creates a new MicroVM struct (does not start the process yet)
    fn new(id: &str, tap_name: &str, ip_addr: &str, gateway: &str) -> Self {
        let socket_path = PathBuf::from(format!("/tmp/firecracker_{}.socket", id));

        Self {
            id: id.to_string(),
            socket_path,
            process: None,
            tap_name: tap_name.to_string(),
            guest_ip: ip_addr.to_string(),
            gateway_ip: gateway.to_string(),
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

        // Command to run firecracker.
        // We point it to the API socket so we can configure it later.
        // Redirect stdout/stderr to null to prevent Firecracker logs from interfering
        let child = Command::new("firecracker")
            .arg("--api-sock")
            .arg(&self.socket_path)
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
    // Raise capabilities for this handler context
    if let Err(e) = network::NetworkManager::raise_ambient_cap_net_admin() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to raise capabilities: {}", e),
        )
            .into_response();
    }

    let vm_id = payload.vm_id;
    let tap_name = format!("tap-{}", vm_id);

    // 1. Host Network Plumbing (Sudo/Cap required)
    if let Err(e) = network::NetworkManager::setup_tap_bridge(&tap_name, "br0").await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Net Error: {}", e),
        )
            .into_response();
    }

    // 2. Instantiate VM Struct
    // Note: We use the constants or payload data here
    let mut vm = MicroVM::new(&vm_id, &tap_name, "172.16.0.2", "172.16.0.1");

    // 3. Spawn Process
    if let Err(e) = vm.start_process().await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // 4. Configure Resources (CPU/RAM)
    if let Err(e) = vm.configure_vm().await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // 5. The Sequence You Asked About (Yes, it goes here!)
    // We await each step. If one fails, we return Error immediately.

    // Set Boot Source
    if let Err(e) = vm.set_boot_source(KERNEL_PATH).await {
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to prepare instance drive: {}", e),
            )
                .into_response();
        }
    };

    // Attach Drive
    if let Err(e) = vm.attach_rootfs(&rootfs_path).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("RootFS Error: {}", e),
        )
            .into_response();
    }

    // Attach Network (Guest Side)
    if let Err(e) = vm.attach_network().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Net Attach Error: {}", e),
        )
            .into_response();
    }

    // 6. Ignite
    if let Err(e) = vm.start_instance().await {
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
        // Return error to user
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "VM crashed during boot (check server logs)".to_string(),
        )
            .into_response();
    }

    // 8. Success! NOW we save state and return 200
    state.vms.lock().await.insert(vm_id.clone(), vm);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "deployed", "id": vm_id })),
    )
        .into_response()
}
#[tokio::main]
async fn main() -> Result<()> {
    // Raise capabilities once at the start for all network operations
    network::NetworkManager::raise_ambient_cap_net_admin()?;

    let shared_state = Arc::new(AppState {
        vms: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/deploy", post(deploy_vm))
        .route("/health", get(|| async { "Aether is running" }))
        .with_state(shared_state.clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("🛸 Aether Control Plane listening on port 3000...");

    axum::serve(listener, app).await?;
    Ok(())
}

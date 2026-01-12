use crate::client::send_put_request;
use crate::config::{Action, BootSource, Drive, MachineConfiguration, NetworkInterface};
use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::process::Command;
use tokio::signal;

mod client;
mod config;
mod network;

// The Hypervisor manages the lifecycle of a single Firecracker process.
struct MicroVM {
    id: String,
    socket_path: PathBuf,
    // We hold the child process to ensure it doesn't become a zombie.
    process: Option<tokio::process::Child>,
}

impl MicroVM {
    /// Creates a new MicroVM struct (does not start the process yet)
    fn new(id: &str) -> Self {
        let socket_path = PathBuf::from(format!("/tmp/firecracker_{}.socket", id));

        Self {
            id: id.to_string(),
            socket_path,
            process: None,
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
            boot_args: Some("console=ttyS0 reboot=k panic=1 pci=off ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off".to_string()),
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
            host_dev_name: "tap0".to_string(),
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

#[tokio::main]
async fn main() -> Result<()> {
    // Raise capabilities once at the start for all network operations
    network::NetworkManager::raise_ambient_cap_net_admin()?;

    let _ = network::NetworkManager::teardown_tap("tap0");

    // Setup Network
    // Ensure you created 'br0' manually once: `sudo ip link add name br0 type bridge && sudo ip link set br0 up`
    network::NetworkManager::setup_tap_bridge("tap0", "br0").await?;

    // 1. Initialize the VM definition
    let mut vm = MicroVM::new("test-vm-01");

    // 2. Start the empty Firecracker process
    vm.start_process().await?;
    vm.configure_vm().await?;

    vm.set_boot_source("/home/axel/aether-platform/resources/vmlinux.bin")
        .await?;
    vm.attach_rootfs("/home/axel/aether-platform/resources/bionic.rootfs.ext4")
        .await?;
    vm.attach_network().await?;
    vm.start_instance().await?;

    println!("✅ Firecracker is running! Socket at: {:?}", vm.socket_path);
    println!("🛑 Press Ctrl+C to stop the VM...");

    // Block the main thread until the interrupt signal (Ctrl+C) is received
    signal::ctrl_c().await.expect("failed to listen for event");

    println!("⚠️ Signal received. Shutting down...");

    // Cleanup
    if let Some(mut child) = vm.process.take() {
        child.kill().await?;
        println!("💀 VM Shutdown.");
    }
    Ok(())
}

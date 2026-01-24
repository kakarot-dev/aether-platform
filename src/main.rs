use crate::client::send_put_request;
use crate::config::{Action, BootSource, Drive, MachineConfiguration, NetworkInterface};
use crate::ipam::IpAllocator;
use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::{broadcast, Mutex};
use tower_http::services::ServeDir;

mod cgroups;
pub mod client;
pub mod config;
pub mod dtos;
mod firewall;
mod ipam;
mod monitor;
pub mod network;
mod routes;

pub const KERNEL_PATH: &str = "/home/axel/aether-platform/resources/vmlinux.bin";
pub const ROOTFS_PATH: &str = "/home/axel/aether-platform/resources/aether-base.ext4";
pub const INSTANCE_DIR: &str = "/tmp/aether-instances";
pub const SNAPSHOTS_DIR: &str = "/home/axel/aether-platform/resources/snapshots";

pub struct AppState {
    pub vms: Mutex<HashMap<String, MicroVM>>,
    pub ipam: Mutex<IpAllocator>,
    pub db: PgPool,
    pub network_manager: network::NetworkManager,
    pub telemetry_tx: broadcast::Sender<String>,
}

// The Hypervisor manages the lifecycle of a single Firecracker process.
pub struct MicroVM {
    pub id: String,
    pub socket_path: PathBuf,
    // We hold the child process to ensure it doesn't become a zombie.
    pub process: Option<tokio::process::Child>,
    pub tap_name: String,
    pub guest_ip: String,
    pub gateway_ip: String,
    pub ip_octet: u8,
}

impl MicroVM {
    /// Creates a new MicroVM struct (does not start the process yet)
    pub fn new(id: &str, tap_name: &str, ip_addr: &str, gateway: &str, ip_octet: u8) -> Self {
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
    pub async fn start_process(&mut self) -> Result<()> {
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
    pub async fn configure_vm(&self) -> Result<()> {
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

    pub async fn set_boot_source(&self, kernel_path: &str) -> Result<()> {
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

    pub async fn attach_rootfs(&self, fs_path: &str) -> Result<()> {
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

    pub async fn start_instance(&self) -> Result<()> {
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

    pub async fn attach_network(&self) -> Result<()> {
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

pub async fn prepare_instance_drive(vm_id: &str) -> Result<String> {
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

    // Create broadcast channel for real-time telemetry
    let (telemetry_tx, _) = broadcast::channel::<String>(1000);

    let shared_state = Arc::new(AppState {
        vms: Mutex::new(HashMap::new()),
        ipam: Mutex::new(IpAllocator::new()),
        db: pool,
        network_manager: net_mgr,
        telemetry_tx,
    });

    // Spawn background metrics monitor
    monitor::spawn_metrics_monitor(shared_state.clone());

    let app = Router::new()
        .route("/api/ws", get(routes::ws_handler))
        .route("/api/deploy", post(routes::deploy_vm))
        .route("/api/stop", post(routes::stop_vm))
        .route("/api/delete", post(routes::delete_vm))
        .route("/api/vms", get(routes::list_vms))
        .route("/api/system", get(routes::system_info))
        .route("/api/health", get(|| async { "Aether is running" }))
        .route("/api/vms/pause", post(routes::pause_vm))
        .route("/api/vms/resume", post(routes::resume_vm))
        .route("/api/vms/snapshot", post(routes::create_snapshot))
        .route("/api/vms/restore", post(routes::restore_vm))
        .route("/api/vms/disk-snapshot", post(routes::create_disk_snapshot))
        .route("/api/vms/restore-disk", post(routes::restore_from_disk_snapshot))
        .route("/api/snapshots", get(routes::list_snapshots))
        .route("/api/snapshots/delete", post(routes::delete_snapshot))
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

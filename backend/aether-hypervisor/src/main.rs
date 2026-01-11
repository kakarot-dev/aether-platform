use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::process::Command;

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
        let child = Command::new("firecracker")
            .arg("--api-sock")
            .arg(&self.socket_path)
            .spawn()
            .context("Failed to spawn firecracker binary")?;

        self.process = Some(child);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize the VM definition
    let mut vm = MicroVM::new("test-vm-01");

    // 2. Start the empty Firecracker process
    vm.start_process().await?;

    println!("✅ Firecracker is running! Socket at: {:?}", vm.socket_path);

    // Keep the main thread alive so the child process doesn't die immediately
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Cleanup (Kill the process)
    if let Some(mut child) = vm.process.take() {
        child.kill().await?;
        println!("💀 Killed Firecracker process.");
    }

    Ok(())
}

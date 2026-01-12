use anyhow::{Context, Result};
use std::process::Command;

pub struct NetworkManager;

impl NetworkManager {
    pub async fn setup_tap_bridge(tap_name: &str, bridge_name: &str) -> Result<()> {
        println!("🔧 Network: Creating TAP device '{}'...", tap_name);
        // 1. Create TAP Device
        // ip tuntap add dev tap0 mode tap user $USER
        let user = std::env::var("USER").unwrap_or("root".to_string());
        run_cmd(
            "ip",
            &[
                "tuntap", "add", "dev", tap_name, "mode", "tap", "user", &user,
            ],
        )?;

        // 2. Set TAP Master (Attach to Bridge)
        // ip link set tap0 master br0
        run_cmd("ip", &["link", "set", tap_name, "master", bridge_name])?;

        // 3. Bring TAP Up
        // ip link set tap0 up
        run_cmd("ip", &["link", "set", tap_name, "up"])?;

        // 4. Assign Gateway IP to the TAP (or the Bridge)
        // Since we are using a Bridge, the IP usually goes on 'br0', not 'tap0'.
        // Ensure your host setup has 172.16.0.1 on br0.
        // Run idempotently (ignore error if IP already exists)
        let _ = run_cmd("ip", &["addr", "add", "172.16.0.1/24", "dev", bridge_name]);
        println!("✅ Network: Interface Ready.");

        Ok(())
    }
    pub fn raise_ambient_cap_net_admin() -> Result<()> {
        use caps::{CapSet, Capability};

        // Raise CAP_NET_ADMIN
        caps::raise(None, CapSet::Effective, Capability::CAP_NET_ADMIN)
            .context("Failed to raise CAP_NET_ADMIN to effective")?;
        caps::raise(None, CapSet::Inheritable, Capability::CAP_NET_ADMIN)
            .context("Failed to raise CAP_NET_ADMIN to inheritable")?;
        caps::raise(None, CapSet::Ambient, Capability::CAP_NET_ADMIN)
            .context("Failed to raise CAP_NET_ADMIN to ambient")?;

        // Also raise CAP_SETPCAP so child processes can manipulate capabilities
        caps::raise(None, CapSet::Effective, Capability::CAP_SETPCAP)
            .context("Failed to raise CAP_SETPCAP to effective")?;
        caps::raise(None, CapSet::Inheritable, Capability::CAP_SETPCAP)
            .context("Failed to raise CAP_SETPCAP to inheritable")?;
        caps::raise(None, CapSet::Ambient, Capability::CAP_SETPCAP)
            .context("Failed to raise CAP_SETPCAP to ambient")?;

        Ok(())
    }
    /// Clean up (Optional, good for testing)
    pub fn teardown_tap(tap_name: &str) -> Result<()> {
        let _ = run_cmd("ip", &["link", "delete", tap_name]);
        Ok(())
    }
}

fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .context(format!("Failed to execute {} {:?}", program, args))?;

    if !status.success() {
        anyhow::bail!("Command failed: {} {:?}", program, args);
    }
    Ok(())
}

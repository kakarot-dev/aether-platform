use anyhow::{Context, Result};
use iptables;
use std::fs;

pub struct FirewallManager {
    ipt: iptables::IPTables,
    host_interface: String,
    original_ip_forward: bool, // Track if we changed ip_forward
}

impl FirewallManager {
    /// Creates a new FirewallManager and detects the default network interface
    pub fn new() -> Result<Self> {
        println!("🔥 Initializing FirewallManager...");

        // Initialize iptables (false = don't use IPv6)
        let ipt = iptables::new(false)
            .map_err(|e| anyhow::anyhow!("Failed to initialize iptables: {}", e))?;

        // Detect the default route interface dynamically
        let host_interface = Self::detect_default_interface()
            .context("Failed to detect default network interface")?;

        // Read current IP forwarding state
        let original_ip_forward = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("Failed to read /proc/sys/net/ipv4/ip_forward")?
            .trim() == "1";

        println!("   ✅ Detected host interface: {}", host_interface);
        println!("   ℹ️  Original IP forwarding: {}", if original_ip_forward { "enabled" } else { "disabled" });

        Ok(Self {
            ipt,
            host_interface,
            original_ip_forward,
        })
    }

    /// Detects the default network interface by parsing `ip route`
    fn detect_default_interface() -> Result<String> {
        let output = std::process::Command::new("ip")
            .args(&["-j", "route", "list", "default"])
            .output()
            .context("Failed to execute 'ip route' command")?;

        if !output.status.success() {
            anyhow::bail!(
                "ip route command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Parse JSON output from ip command
        let routes: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
            .context("Failed to parse ip route JSON output")?;

        routes
            .first()
            .and_then(|route| route["dev"].as_str())
            .map(|iface| iface.to_string())
            .ok_or_else(|| anyhow::anyhow!("No default route found"))
    }

    /// Enable IP forwarding in the Linux kernel
    pub fn enable_ip_forwarding(&self) -> Result<()> {
        let current = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("Failed to read /proc/sys/net/ipv4/ip_forward")?;

        if current.trim() == "1" {
            println!("ℹ️  IP forwarding already enabled");
            return Ok(());
        }

        fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .context("Failed to enable IP forwarding - ensure you have CAP_NET_ADMIN capability")?;

        println!("✅ IP forwarding enabled");
        Ok(())
    }

    /// Setup global NAT rules for VM subnet
    pub fn setup_nat(&self, bridge_name: &str, vm_subnet: &str) -> Result<()> {
        println!("🔥 Setting up NAT firewall rules...");

        // Rule 1: MASQUERADE for VM subnet (NAT)
        let masq_rule = format!("-o {} -s {} -j MASQUERADE", self.host_interface, vm_subnet);
        let exists = self.ipt.exists("nat", "POSTROUTING", &masq_rule)
            .map_err(|e| anyhow::anyhow!("Failed to check MASQUERADE rule: {}", e))?;

        if !exists {
            self.ipt
                .append("nat", "POSTROUTING", &masq_rule)
                .map_err(|e| anyhow::anyhow!("Failed to add MASQUERADE rule: {}", e))?;
            println!("   ✅ Added MASQUERADE rule for {}", vm_subnet);
        } else {
            println!("   ℹ️  MASQUERADE rule already exists");
        }

        // Rule 2: Allow established/related connections (stateful firewall)
        let conntrack_rule = "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
        let exists = self.ipt.exists("filter", "FORWARD", conntrack_rule)
            .map_err(|e| anyhow::anyhow!("Failed to check conntrack rule: {}", e))?;

        if !exists {
            self.ipt
                .insert("filter", "FORWARD", conntrack_rule, 1)
                .map_err(|e| anyhow::anyhow!("Failed to add conntrack rule: {}", e))?;
            println!("   ✅ Added conntrack FORWARD rule");
        } else {
            println!("   ℹ️  Conntrack rule already exists");
        }

        // Rule 3: Allow traffic from bridge to internet
        let forward_rule = format!("-i {} -o {} -j ACCEPT", bridge_name, self.host_interface);
        let exists = self.ipt.exists("filter", "FORWARD", &forward_rule)
            .map_err(|e| anyhow::anyhow!("Failed to check FORWARD rule: {}", e))?;

        if !exists {
            self.ipt
                .append("filter", "FORWARD", &forward_rule)
                .map_err(|e| anyhow::anyhow!("Failed to add FORWARD rule: {}", e))?;
            println!("   ✅ Added FORWARD rule for {}", bridge_name);
        } else {
            println!("   ℹ️  FORWARD rule already exists");
        }

        // Rule 4: VM isolation (prevent VM-to-VM communication via bridge)
        let isolation_rule = format!("-i {} -o {} -j DROP", bridge_name, bridge_name);
        let exists = self.ipt.exists("filter", "FORWARD", &isolation_rule)
            .map_err(|e| anyhow::anyhow!("Failed to check VM isolation rule: {}", e))?;

        if !exists {
            self.ipt
                .insert("filter", "FORWARD", &isolation_rule, 1)
                .map_err(|e| anyhow::anyhow!("Failed to add VM isolation rule: {}", e))?;
            println!("   ✅ Added VM isolation rule (prevents VM-to-VM traffic)");
        } else {
            println!("   ℹ️  VM isolation rule already exists");
        }

        println!("✅ NAT firewall rules configured successfully");
        Ok(())
    }

    /// Cleanup NAT rules when shutting down
    pub fn cleanup_nat(&self, bridge_name: &str, vm_subnet: &str) -> Result<()> {
        println!("🗑️  Cleaning up NAT firewall rules...");

        // Remove MASQUERADE rule
        let masq_rule = format!("-o {} -s {} -j MASQUERADE", self.host_interface, vm_subnet);
        let _ = self.ipt.delete("nat", "POSTROUTING", &masq_rule);

        // Remove FORWARD rule
        let forward_rule = format!("-i {} -o {} -j ACCEPT", bridge_name, self.host_interface);
        let _ = self.ipt.delete("filter", "FORWARD", &forward_rule);

        // Remove conntrack rule
        let conntrack_rule = "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
        let _ = self.ipt.delete("filter", "FORWARD", conntrack_rule);

        // Remove VM isolation rule
        let isolation_rule = format!("-i {} -o {} -j DROP", bridge_name, bridge_name);
        let _ = self.ipt.delete("filter", "FORWARD", &isolation_rule);

        println!("   ✅ NAT rules cleaned up");
        Ok(())
    }

    /// Restore IP forwarding to its original state
    fn restore_ip_forwarding(&self) -> Result<()> {
        // Only restore if we changed it (it was disabled before)
        if !self.original_ip_forward {
            println!("🔄 Restoring IP forwarding to original state (disabled)...");
            fs::write("/proc/sys/net/ipv4/ip_forward", "0")
                .context("Failed to restore IP forwarding")?;
            println!("   ✅ IP forwarding restored to disabled");
        } else {
            println!("   ℹ️  IP forwarding was already enabled, leaving as-is");
        }
        Ok(())
    }
}

impl Drop for FirewallManager {
    fn drop(&mut self) {
        println!("\n🛑 FirewallManager shutting down...");
        // Best-effort cleanup on drop
        let _ = self.cleanup_nat("br0", "172.16.0.0/24");
        let _ = self.restore_ip_forwarding();
        println!("✅ Firewall cleanup complete\n");
    }
}

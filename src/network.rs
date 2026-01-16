use anyhow::{Context, Result};
use futures_util::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode as FileMode;
use nix::unistd::close;
use rtnetlink::{new_connection, Handle};
use std::ffi::CString;

// ioctl constants for TAP/TUN device creation
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const TUNSETPERSIST: libc::c_ulong = 0x400454cb;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

// ifreq structure for ioctl calls
#[repr(C)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_flags: libc::c_short,
    _padding: [u8; 22], // Padding to match the C struct size
}

pub struct NetworkManager {
    handle: Handle,
}

impl NetworkManager {
    /// Creates a new NetworkManager with an active netlink connection
    pub async fn new() -> Result<Self> {
        let (connection, handle, _) =
            new_connection().context("Failed to create netlink connection")?;

        // Spawn the netlink connection handler in the background
        tokio::spawn(connection);

        Ok(Self { handle })
    }

    /// Creates a persistent TAP device using native ioctl calls
    /// The device will remain after this function returns, allowing Firecracker to open it
    fn create_tap_device(tap_name: &str) -> Result<()> {
        println!(
            "🔧 Creating TAP device '{}' using native ioctl...",
            tap_name
        );

        // Open /dev/net/tun
        let fd = open("/dev/net/tun", OFlag::O_RDWR, FileMode::empty())
            .context("Failed to open /dev/net/tun - ensure TUN/TAP kernel module is loaded")?;

        // Prepare the interface request structure
        let mut ifr = ifreq {
            ifr_name: [0; libc::IF_NAMESIZE],
            ifr_flags: IFF_TAP | IFF_NO_PI,
            _padding: [0; 22],
        };

        // Copy the TAP device name into the structure
        let name_cstr = CString::new(tap_name).context("Invalid TAP device name")?;
        let name_bytes = name_cstr.as_bytes_with_nul();

        if name_bytes.len() > libc::IF_NAMESIZE {
            anyhow::bail!(
                "TAP device name too long (max {} chars)",
                libc::IF_NAMESIZE - 1
            );
        }

        for (i, &byte) in name_bytes.iter().enumerate() {
            ifr.ifr_name[i] = byte as libc::c_char;
        }

        // Make the ioctl call to create the TAP device
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr as *const ifreq) };

        if ret < 0 {
            let _ = close(fd);
            anyhow::bail!(
                "TUNSETIFF ioctl failed: {}. Ensure you have CAP_NET_ADMIN capability",
                std::io::Error::last_os_error()
            );
        }

        // Make the TAP device persistent so it survives FD closure
        // This allows Firecracker to open and use the device
        let persist_ret = unsafe { libc::ioctl(fd, TUNSETPERSIST, 1) };

        if persist_ret < 0 {
            let _ = close(fd);
            anyhow::bail!(
                "TUNSETPERSIST ioctl failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Close the FD - the TAP device will remain because it's persistent
        close(fd).context("Failed to close TAP device file descriptor")?;

        println!(
            "   ✅ TAP device '{}' created successfully (persistent)",
            tap_name
        );
        Ok(())
    }

    /// Sets up the complete network stack for a VM
    /// Creates TAP device, attaches to bridge, brings it up
    pub async fn setup_tap_bridge(&self, tap_name: &str, bridge_name: &str) -> Result<()> {
        // 1. Create persistent TAP device
        Self::create_tap_device(tap_name)?;

        // 2. Get interface indices via netlink
        let tap_index = self
            .get_link_index(tap_name)
            .await
            .context("Failed to get TAP device index after creation")?;

        let bridge_index = self.get_link_index(bridge_name).await.context(format!(
            "Bridge '{}' not found - create it first with 'ip link add name {} type bridge'",
            bridge_name, bridge_name
        ))?;

        // 3. Attach TAP to bridge (set controller)
        println!("🔗 Attaching '{}' to bridge '{}'...", tap_name, bridge_name);
        self.handle
            .link()
            .set(tap_index)
            .controller(bridge_index)
            .execute()
            .await
            .context("Failed to attach TAP to bridge")?;

        // 4. Bring TAP interface up
        println!("⬆️  Bringing TAP interface '{}' up...", tap_name);
        self.handle
            .link()
            .set(tap_index)
            .up()
            .execute()
            .await
            .context("Failed to bring TAP interface up")?;

        // 5. Assign gateway IP to bridge (if not already assigned)
        // This is idempotent - we ignore errors if IP already exists
        let gateway_ip = "172.16.0.1/24";
        match self.assign_ip_to_interface(bridge_name, gateway_ip).await {
            Ok(_) => println!(
                "   ✅ Assigned gateway IP {} to {}",
                gateway_ip, bridge_name
            ),
            Err(e) => println!("   ℹ️  IP assignment note: {} (may already exist)", e),
        }

        println!("✅ Network: Interface '{}' ready.", tap_name);
        Ok(())
    }

    /// Assigns an IP address to an interface using netlink
    async fn assign_ip_to_interface(
        &self,
        interface_name: &str,
        ip_with_prefix: &str,
    ) -> Result<()> {
        let index = self.get_link_index(interface_name).await?;
        let network: IpNetwork = ip_with_prefix
            .parse()
            .context("Invalid IP address/prefix format")?;

        self.handle
            .address()
            .add(index, network.ip(), network.prefix())
            .execute()
            .await
            .context("Failed to assign IP address")?;

        Ok(())
    }

    /// Brings a network interface up
    #[allow(dead_code)]
    pub async fn set_link_up(&self, interface_name: &str) -> Result<()> {
        let index = self.get_link_index(interface_name).await?;

        self.handle
            .link()
            .set(index)
            .up()
            .execute()
            .await
            .context(format!("Failed to bring interface '{}' up", interface_name))?;

        Ok(())
    }

    /// Deletes a TAP device using netlink
    pub async fn teardown_tap(&self, tap_name: &str) -> Result<()> {
        // Check if device exists first
        match self.get_link_index(tap_name).await {
            Ok(index) => {
                println!("🗑️  Deleting TAP device '{}'...", tap_name);
                self.handle
                    .link()
                    .del(index)
                    .execute()
                    .await
                    .context("Failed to delete TAP device")?;
                println!("   ✅ TAP device deleted");
                Ok(())
            }
            Err(_) => {
                println!(
                    "   ℹ️  TAP device '{}' doesn't exist, skipping deletion",
                    tap_name
                );
                Ok(())
            }
        }
    }

    /// Gets the interface index by name using netlink
    async fn get_link_index(&self, name: &str) -> Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        if let Some(link) = links
            .try_next()
            .await
            .context("Failed to query network interfaces")?
        {
            Ok(link.header.index)
        } else {
            anyhow::bail!("Network interface '{}' not found", name)
        }
    }

    /// Raises CAP_NET_ADMIN capability (still needed for some operations)
    pub fn raise_ambient_cap_net_admin() -> Result<()> {
        use caps::{CapSet, Capability};

        println!("🔑 Raising network capabilities...");

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

        println!("✅ Capabilities raised");
        Ok(())
    }
}

// Note: TAP devices are created as persistent (TUNSETPERSIST) so they survive after
// the creating process closes the file descriptor. This allows Firecracker to open
// and use the device. The device must be explicitly deleted via netlink when no longer needed.

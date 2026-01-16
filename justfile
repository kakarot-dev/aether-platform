# Build the hypervisor with CAP_NET_ADMIN and CAP_SETPCAP capabilities
build:
    cargo build --release
    sudo setcap cap_net_admin,cap_setpcap+eip target/release/aether-hypervisor
    @echo "✅ Built with CAP_NET_ADMIN and CAP_SETPCAP"

# Build and run the hypervisor
run: build
    ./target/release/aether-hypervisor

# Development build (debug mode)
dev:
    cargo build
    sudo setcap cap_net_admin,cap_setpcap+eip target/debug/aether-hypervisor
    ./target/debug/aether-hypervisor

# Check code without building
check:
    cargo check

# Run tests
test:
    cargo test

# Clean build artifacts
clean:
    cargo clean

# Clean up all VMs and resources (TAP devices, processes, files)
cleanup:
    @echo "🧹 Cleaning up all VM resources..."
    @echo "   -> Killing Firecracker and hypervisor processes..."
    -pkill -9 firecracker 2>/dev/null || true
    -pkill -9 aether-hypervisor 2>/dev/null || true
    @echo "   -> Removing TAP devices (no tap- prefix)..."
    -@for tap in $$(ip link show | grep -oP '^\d+: \K[a-z0-9-]+(?=:)' | grep -v -E '^(lo|eth|wlan|br|docker|veth)'); do \
        sudo ip link delete $$tap 2>/dev/null || true; \
    done
    @echo "   -> Removing temporary files..."
    -rm -rf /tmp/aether-logs /tmp/aether-instances /tmp/firecracker_*.socket
    @echo "   -> Cleaning up iptables rules..."
    -sudo iptables -t nat -D POSTROUTING -o eth0 -s 172.16.0.0/24 -j MASQUERADE 2>/dev/null || true
    -sudo iptables -t filter -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    -sudo iptables -t filter -D FORWARD -i br0 -o eth0 -j ACCEPT 2>/dev/null || true
    -sudo iptables -t filter -D FORWARD -i br0 -o br0 -j DROP 2>/dev/null || true
    @echo "✅ Cleanup complete!"

# Verify cleanup - check if all VM resources are gone
verify-cleanup VM_ID:
    @echo "🔍 Verifying cleanup for VM: {{VM_ID}}"
    @echo ""
    @echo "TAP device:"
    @ip link show {{VM_ID}} 2>&1 | grep -q "does not exist" && echo "  ✅ Cleaned up" || echo "  ❌ Still exists"
    @echo ""
    @echo "Socket file:"
    @test ! -f /tmp/firecracker_{{VM_ID}}.socket && echo "  ✅ Cleaned up" || echo "  ❌ Still exists"
    @echo ""
    @echo "Disk image:"
    @test ! -f /tmp/aether-instances/rootfs-{{VM_ID}}.ext4 && echo "  ✅ Cleaned up" || echo "  ❌ Still exists"
    @echo ""
    @echo "Console log:"
    @test ! -f /tmp/aether-logs/{{VM_ID}}-console.log && echo "  ✅ Cleaned up" || echo "  ❌ Still exists"
    @echo ""
    @echo "Error log:"
    @test ! -f /tmp/aether-logs/{{VM_ID}}-error.log && echo "  ✅ Cleaned up" || echo "  ❌ Still exists"

# Check firewall status
check-firewall:
    @echo "🔥 Firewall Status"
    @echo ""
    @echo "=== IP Forwarding ==="
    @echo -n "Status: "
    @cat /proc/sys/net/ipv4/ip_forward | grep -q "1" && echo "✅ Enabled" || echo "❌ Disabled"
    @echo ""
    @echo "=== NAT Rules (POSTROUTING) ==="
    @sudo iptables -t nat -L POSTROUTING -n -v | grep -E "Chain|MASQUERADE|172.16" || echo "No NAT rules found"
    @echo ""
    @echo "=== FORWARD Rules ==="
    @sudo iptables -t filter -L FORWARD -n -v | grep -E "Chain|br0|eth0|DROP" | head -10 || echo "No FORWARD rules found"

# Test deployment and cleanup cycle
test-vm-lifecycle:
    @echo "🧪 Testing VM Lifecycle..."
    @echo ""
    @echo "Step 1: Deploy test VM"
    curl -s -X POST http://localhost:3000/deploy -H 'Content-Type: application/json' -d '{"vm_id":"lifecycle-test"}' | jq .
    @echo ""
    @echo "Step 2: Wait 3 seconds for VM to boot..."
    @sleep 3
    @echo ""
    @echo "Step 3: Verify VM is running"
    @ip link show lifecycle-test >/dev/null 2>&1 && echo "  ✅ TAP device exists" || echo "  ❌ TAP device missing"
    @test -f /tmp/firecracker_lifecycle-test.socket && echo "  ✅ Socket exists" || echo "  ❌ Socket missing"
    @test -f /tmp/aether-instances/rootfs-lifecycle-test.ext4 && echo "  ✅ Disk exists" || echo "  ❌ Disk missing"
    @echo ""
    @echo "Step 4: Stop VM"
    curl -s -X POST http://localhost:3000/stop -H 'Content-Type: application/json' -d '{"vm_id":"lifecycle-test"}' | jq .
    @echo ""
    @echo "Step 5: Wait 1 second for cleanup..."
    @sleep 1
    @echo ""
    @echo "Step 6: Verify cleanup"
    just verify-cleanup lifecycle-test

# Setup system (one-time: create netdev group and add user)
setup:
    sudo groupadd -f netdev
    sudo usermod -a -G netdev $(USER)
    @echo "✅ Setup complete! Log out and back in for group changes to take effect."

# Format code
fmt:
    cargo fmt

# Run clippy linter
lint:
    cargo clippy

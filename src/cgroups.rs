use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Clone)]
pub struct CgroupStats {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub memory_limit_bytes: u64,
    pub memory_usage_percent: f64,
    pub throttled_periods: u64,
    pub total_periods: u64,
    pub throttle_percent: f64,
}

#[derive(Clone)]
struct StatsSample {
    timestamp: u64,
    periods: u64,
    throttled: u64,
}

lazy_static::lazy_static! {
    static ref STATS_CACHE: Mutex<HashMap<String, StatsSample>> = Mutex::new(HashMap::new());
}

fn get_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// Cgroup v1 paths (for hybrid mode systems)
const CPU_CGROUP_ROOT: &str = "/sys/fs/cgroup/cpu/aether";
const MEMORY_CGROUP_ROOT: &str = "/sys/fs/cgroup/memory/aether";

/// Initialize the cgroup hierarchy for Aether VMs
pub fn initialize() -> Result<()> {
    // Create CPU cgroup hierarchy
    let cpu_path = Path::new(CPU_CGROUP_ROOT);
    if !cpu_path.exists() {
        println!("🔒 Cgroups: Creating CPU hierarchy at {}", CPU_CGROUP_ROOT);
        fs::create_dir_all(cpu_path).context("Failed to create CPU cgroup root")?;
    }

    // Create Memory cgroup hierarchy
    let mem_path = Path::new(MEMORY_CGROUP_ROOT);
    if !mem_path.exists() {
        println!("🔒 Cgroups: Creating Memory hierarchy at {}", MEMORY_CGROUP_ROOT);
        fs::create_dir_all(mem_path).context("Failed to create Memory cgroup root")?;
    }

    Ok(())
}

/// Create a cgroup for a specific VM
pub fn create_vm_cgroup(vm_id: &str) -> Result<()> {
    // Create CPU cgroup
    let cpu_path = format!("{}/{}", CPU_CGROUP_ROOT, vm_id);
    fs::create_dir_all(&cpu_path).context("Failed to create CPU cgroup")?;

    // Create Memory cgroup
    let mem_path = format!("{}/{}", MEMORY_CGROUP_ROOT, vm_id);
    fs::create_dir_all(&mem_path).context("Failed to create Memory cgroup")?;

    Ok(())
}

/// Apply CPU and memory limits to a VM's cgroup
/// cpu_quota_us: CPU quota in microseconds (100000 = 100% of one core, 20000 = 20%)
/// memory_bytes: Memory limit in bytes
pub fn apply_limits(vm_id: &str, cpu_quota_us: u32, memory_bytes: u64) -> Result<()> {
    let cpu_path = format!("{}/{}", CPU_CGROUP_ROOT, vm_id);
    let mem_path = format!("{}/{}", MEMORY_CGROUP_ROOT, vm_id);

    // CPU Limit (cgroup v1 uses cpu.cfs_quota_us and cpu.cfs_period_us)
    fs::write(format!("{}/cpu.cfs_period_us", cpu_path), "100000")
        .context("Failed to set cpu.cfs_period_us")?;
    fs::write(format!("{}/cpu.cfs_quota_us", cpu_path), cpu_quota_us.to_string())
        .context("Failed to set cpu.cfs_quota_us")?;

    // Memory Limit (cgroup v1 uses memory.limit_in_bytes)
    fs::write(format!("{}/memory.limit_in_bytes", mem_path), memory_bytes.to_string())
        .context("Failed to set memory.limit_in_bytes")?;

    // Disable swap
    let _ = fs::write(format!("{}/memory.swappiness", mem_path), "0");

    Ok(())
}

/// Add a process to the VM's cgroup
pub fn add_process(vm_id: &str, pid: u32) -> Result<()> {
    let pid_str = pid.to_string();

    // Add to CPU cgroup
    let cpu_tasks = format!("{}/{}/tasks", CPU_CGROUP_ROOT, vm_id);
    fs::write(&cpu_tasks, &pid_str).context("Failed to add process to CPU cgroup")?;

    // Add to Memory cgroup
    let mem_tasks = format!("{}/{}/tasks", MEMORY_CGROUP_ROOT, vm_id);
    fs::write(&mem_tasks, &pid_str).context("Failed to add process to Memory cgroup")?;

    Ok(())
}

/// Remove a VM's cgroup (call after process is terminated)
pub fn remove_vm_cgroup(vm_id: &str) -> Result<()> {
    // Remove CPU cgroup
    let cpu_path = format!("{}/{}", CPU_CGROUP_ROOT, vm_id);
    if Path::new(&cpu_path).exists() {
        let _ = fs::remove_dir(&cpu_path);
    }

    // Remove Memory cgroup
    let mem_path = format!("{}/{}", MEMORY_CGROUP_ROOT, vm_id);
    if Path::new(&mem_path).exists() {
        let _ = fs::remove_dir(&mem_path);
    }

    // Clean up stats cache
    let mut cache = STATS_CACHE.lock().unwrap();
    cache.remove(vm_id);

    Ok(())
}

/// Read current cgroup statistics for a VM
pub fn get_stats(vm_id: &str) -> Result<CgroupStats> {
    let cpu_path = format!("{}/{}", CPU_CGROUP_ROOT, vm_id);
    let mem_path = format!("{}/{}", MEMORY_CGROUP_ROOT, vm_id);

    // Read CPU stats
    let cpu_stat_content = fs::read_to_string(format!("{}/cpu.stat", cpu_path))
        .context("Failed to read cpu.stat")?;

    let mut total_periods = 0u64;
    let mut throttled_periods = 0u64;

    for line in cpu_stat_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            match parts[0] {
                "nr_periods" => total_periods = parts[1].parse().unwrap_or(0),
                "nr_throttled" => throttled_periods = parts[1].parse().unwrap_or(0),
                _ => {}
            }
        }
    }

    // Calculate rate-based stats using previous sample
    let now = get_timestamp_ms();
    let mut cache = STATS_CACHE.lock().unwrap();

    let (throttle_percent, cpu_usage_percent) = if let Some(prev) = cache.get(vm_id) {
        let time_delta = (now - prev.timestamp) as f64 / 1000.0; // seconds

        if time_delta > 0.1 {
            // Calculate deltas
            let period_delta = total_periods.saturating_sub(prev.periods);
            let throttled_delta = throttled_periods.saturating_sub(prev.throttled);

            // Current throttle percentage (based on delta)
            let current_throttle = if period_delta > 0 {
                (throttled_delta as f64 / period_delta as f64) * 100.0
            } else {
                0.0
            };

            // CPU usage estimate: if throttled heavily, using ~20%
            let current_cpu = if current_throttle > 50.0 {
                20.0 // At quota limit
            } else {
                20.0 * (current_throttle / 100.0) // Proportional
            };

            (current_throttle, current_cpu)
        } else {
            (0.0, 0.0) // Too soon, return zeros
        }
    } else {
        (0.0, 0.0) // First sample
    };

    // Update cache with current sample
    cache.insert(vm_id.to_string(), StatsSample {
        timestamp: now,
        periods: total_periods,
        throttled: throttled_periods,
    });
    drop(cache);

    // Read memory stats
    let memory_usage_bytes = fs::read_to_string(format!("{}/memory.usage_in_bytes", mem_path))
        .context("Failed to read memory.usage_in_bytes")?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);

    let memory_limit_bytes = fs::read_to_string(format!("{}/memory.limit_in_bytes", mem_path))
        .context("Failed to read memory.limit_in_bytes")?
        .trim()
        .parse::<u64>()
        .unwrap_or(1);

    let memory_usage_percent = (memory_usage_bytes as f64 / memory_limit_bytes as f64) * 100.0;

    Ok(CgroupStats {
        cpu_usage_percent,
        memory_usage_bytes,
        memory_limit_bytes,
        memory_usage_percent,
        throttled_periods,
        total_periods,
        throttle_percent,
    })
}

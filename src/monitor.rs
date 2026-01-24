use std::sync::Arc;
use std::time::Duration;

use crate::{cgroups, AppState};

/// Spawns a background task that collects metrics from all running VMs
/// and broadcasts them via the telemetry channel.
pub fn spawn_metrics_monitor(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));

        loop {
            interval.tick().await;

            // Collect VM IDs from the hashmap
            let vm_ids: Vec<String> = {
                state.vms.lock().await.keys().cloned().collect()
            };

            for vm_id in vm_ids {
                if let Ok(stats) = cgroups::get_stats(&vm_id) {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis();

                    let msg = serde_json::json!({
                        "type": "metrics",
                        "vm_id": vm_id,
                        "cpu": stats.cpu_usage_percent,
                        "memory": stats.memory_usage_percent,
                        "memory_bytes": stats.memory_usage_bytes,
                        "memory_limit_bytes": stats.memory_limit_bytes,
                        "throttle": stats.throttle_percent,
                        "throttled_periods": stats.throttled_periods,
                        "total_periods": stats.total_periods,
                        "ts": ts
                    });

                    // Send to broadcast channel (ignore errors if no subscribers)
                    let _ = state.telemetry_tx.send(msg.to_string());
                }
            }
        }
    });
}

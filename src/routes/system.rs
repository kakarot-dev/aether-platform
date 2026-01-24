use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::dtos::SystemInfo;

pub async fn system_info() -> impl IntoResponse {
    // Get host IP address by reading network interfaces
    let host_ip = std::process::Command::new("sh")
        .arg("-c")
        .arg("ip route get 1 | awk '{print $7; exit}'")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "N/A".to_string());

    // Get primary interface name
    let interface = std::process::Command::new("sh")
        .arg("-c")
        .arg("ip route get 1 | awk '{print $5; exit}'")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "eth0".to_string());

    let info = SystemInfo {
        host_ip,
        bridge_ip: "172.16.0.1".to_string(),
        vm_subnet: "172.16.0.0/24".to_string(),
        interface,
    };

    (StatusCode::OK, Json(info)).into_response()
}

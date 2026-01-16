use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct DeployVmRequest {
    pub vm_id: String,
}

#[derive(Deserialize)]
pub struct StopVmRequest {
    pub vm_id: String,
}

#[derive(Serialize)]
pub struct VmStatus {
    pub id: String,
    pub ip: String,
    pub status: String,
    pub tap: String,
}

#[derive(Serialize)]
pub struct SystemInfo {
    pub host_ip: String,
    pub bridge_ip: String,
    pub vm_subnet: String,
    pub interface: String,
}

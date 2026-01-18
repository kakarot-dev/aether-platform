use crate::cgroups::CgroupStats;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct DeployVmRequest {
    pub vm_id: String,
}

#[derive(Deserialize)]
pub struct StopVmRequest {
    pub vm_id: String,
}

#[derive(Deserialize)]
pub struct DeleteVmRequest {
    pub vm_id: String,
}

#[derive(Serialize)]
pub struct VmStatus {
    pub id: String,
    pub ip: String,
    pub status: String,
    pub tap: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<CgroupStats>,
}

#[derive(Serialize)]
pub struct SystemInfo {
    pub host_ip: String,
    pub bridge_ip: String,
    pub vm_subnet: String,
    pub interface: String,
}

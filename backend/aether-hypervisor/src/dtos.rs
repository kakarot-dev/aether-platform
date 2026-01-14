use serde::Deserialize;

#[derive(Deserialize)]
pub struct DeployVmRequest {
    pub vm_id: String,
}

#[derive(serde::Deserialize)]
pub struct StopVmRequest {
    pub vm_id: String,
}

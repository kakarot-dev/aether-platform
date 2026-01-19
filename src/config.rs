use serde::Serialize;

#[derive(Serialize)]
pub struct MachineConfiguration {
    pub vcpu_count: i32,
    pub mem_size_mib: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smt: Option<bool>,
}

#[derive(Serialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
}

#[derive(Serialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Serialize)]
pub struct Action {
    pub action_type: String, // Must be "InstanceStart"
}

#[derive(Serialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub host_dev_name: String,
}

#[derive(Serialize)]
pub struct VmState {
    pub state: String, // "Paused" or "Resumed"
}

#[derive(Serialize)]
pub struct SnapshotCreate {
    pub snapshot_type: String, // "Full"
    pub snapshot_path: String,
    pub mem_file_path: String,
}

#[derive(Serialize)]
pub struct SnapshotLoad {
    pub snapshot_path: String,
    pub mem_file_path: String,
    pub enable_diff_snapshots: bool,
    pub resume_vm: bool,
}

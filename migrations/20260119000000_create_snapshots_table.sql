-- First, add unique constraint to vms.name if it doesn't exist
ALTER TABLE vms ADD CONSTRAINT vms_name_unique UNIQUE (name);

-- Create snapshots table
CREATE TABLE snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id VARCHAR(255) NOT NULL REFERENCES vms(name),
    snapshot_path VARCHAR(512) NOT NULL,
    mem_file_path VARCHAR(512) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    file_size_mb INTEGER,
    description TEXT
);

CREATE INDEX idx_snapshots_vm_id ON snapshots(vm_id);
CREATE INDEX idx_snapshots_created_at ON snapshots(created_at DESC);

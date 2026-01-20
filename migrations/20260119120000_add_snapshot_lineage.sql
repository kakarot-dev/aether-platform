-- Add snapshot lineage tracking to vms table
ALTER TABLE vms ADD COLUMN created_from_snapshot_id UUID REFERENCES snapshots(id);

CREATE INDEX idx_vms_snapshot_lineage ON vms(created_from_snapshot_id);

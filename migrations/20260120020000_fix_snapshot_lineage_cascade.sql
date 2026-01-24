-- Fix snapshot lineage foreign key to allow snapshot deletion
-- When a snapshot is deleted, VMs spawned from it will have their lineage cleared (SET NULL)
-- instead of blocking the delete operation

ALTER TABLE vms DROP CONSTRAINT IF EXISTS vms_created_from_snapshot_id_fkey;

ALTER TABLE vms
ADD CONSTRAINT vms_created_from_snapshot_id_fkey
FOREIGN KEY (created_from_snapshot_id) REFERENCES snapshots(id) ON DELETE SET NULL;

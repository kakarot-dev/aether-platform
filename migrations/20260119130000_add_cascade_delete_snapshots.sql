-- Drop existing foreign key constraint
ALTER TABLE snapshots DROP CONSTRAINT IF EXISTS snapshots_vm_id_fkey;

-- Re-add foreign key with CASCADE delete
-- When a VM is deleted, all its snapshots will be automatically deleted from DB
ALTER TABLE snapshots
ADD CONSTRAINT snapshots_vm_id_fkey
FOREIGN KEY (vm_id) REFERENCES vms(name) ON DELETE CASCADE;

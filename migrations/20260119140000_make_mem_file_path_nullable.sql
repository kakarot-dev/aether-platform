-- Make mem_file_path nullable to support disk-only snapshots
-- Full VM snapshots (pause/play) have both snapshot_path and mem_file_path
-- Disk-only snapshots have snapshot_path but NULL mem_file_path
ALTER TABLE snapshots ALTER COLUMN mem_file_path DROP NOT NULL;

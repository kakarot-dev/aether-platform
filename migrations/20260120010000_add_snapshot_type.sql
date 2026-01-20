-- Add snapshot_type to distinguish between user snapshots and temporary pause snapshots
-- user: User-created snapshots (shown in UI)
-- temp: Temporary pause snapshots (hidden from UI, deleted on resume)
ALTER TABLE snapshots ADD COLUMN snapshot_type VARCHAR(20) DEFAULT 'user' NOT NULL;

-- Create index for faster filtering
CREATE INDEX idx_snapshots_type ON snapshots(snapshot_type);

-- Add name field to snapshots for short identifiers
-- name is required, description is optional additional info
ALTER TABLE snapshots ADD COLUMN name VARCHAR(255);

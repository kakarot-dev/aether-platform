-- migrations/<timestamp>_create_vms_table.sql

CREATE TABLE vms (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'running', 'stopped', 'failed'
    ip_address VARCHAR(15),      -- '172.16.0.2'
    tap_interface VARCHAR(50),   -- 'tap-uuid'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pid INTEGER                  -- Store the OS process ID (optional but useful)
);

-- +goose Up
-- Retention base of the audit chain (FR-I.31 / FR-I.37). The retention job
-- deletes the oldest audit_log rows once they exceed the configured
-- lifetime. base_seq / base_hash record the sequence_no and entry_hash of
-- the newest row it deleted: the oldest surviving row must chain onto
-- base_hash. Both are bound by head_mac (see internal/audit), so deleting
-- old rows without the chain key stays detectable. 0 / '' = never pruned.
ALTER TABLE audit_head ADD COLUMN base_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_head ADD COLUMN base_hash TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE audit_head DROP COLUMN base_hash;
ALTER TABLE audit_head DROP COLUMN base_seq;

-- +goose Up
-- +goose StatementBegin

-- ---------------------------------------------------------------------------
-- audit_head — single-row, HMAC-sealed anchor of the audit chain (FR-E.1/3).
--
-- head_seq / head_hash pin the newest audit_log row so that deleting the
-- tail is detected. legacy_until is the cut-over: rows with
-- sequence_no <= legacy_until were written before the chain was keyed and
-- verify as plain SHA-256; later rows verify as HMAC-SHA256. It is set
-- here, once, to the highest sequence_no present at migration time.
-- broken_seq is a sticky "first broken entry" marker recorded by the
-- writer. head_mac (empty until the first keyed write) binds all of the
-- above to the audit chain key; see internal/audit.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_head (
    id           SMALLINT PRIMARY KEY CHECK (id = 1),
    legacy_until BIGINT   NOT NULL DEFAULT 0,
    head_seq     BIGINT   NOT NULL DEFAULT 0,
    head_hash    TEXT     NOT NULL DEFAULT '',
    broken_seq   BIGINT   NOT NULL DEFAULT 0,
    head_mac     TEXT     NOT NULL DEFAULT ''
);

INSERT INTO audit_head (id, legacy_until, head_seq, head_hash, broken_seq, head_mac)
SELECT 1, COALESCE(MAX(sequence_no), 0), 0, '', 0, '' FROM audit_log;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_head;
-- +goose StatementEnd

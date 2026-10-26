-- +goose Up
-- +goose StatementBegin
-- Last TOTP time-step accepted for this admin. A code is accepted only for a
-- strictly later step, so a code observed in transit (or shoulder-surfed)
-- cannot be replayed within its ±30 s validity window.
ALTER TABLE admins ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE admins DROP COLUMN totp_last_step;
-- +goose StatementEnd

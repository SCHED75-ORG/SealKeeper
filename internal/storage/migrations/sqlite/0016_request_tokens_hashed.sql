-- +goose Up
-- +goose StatementBegin
-- request_tokens.token held the reveal bearer token verbatim: a database
-- dump or backup yielded live reveal links. The column now stores only
-- hex(SHA-256("sealkeeper-reveal-token:" || token)) and is renamed to say
-- so. SQLite has no SHA-256 to convert rows in place, so pending rows are
-- dropped (same on Postgres, for parity): links issued before the upgrade
-- (15 min TTL) stop working and their recipients request a new one.
-- user_sessions is never written and references the column; it is
-- emptied first.
DELETE FROM user_sessions;
DELETE FROM request_tokens;
ALTER TABLE request_tokens RENAME COLUMN token TO token_hash;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Digests are not tokens: drop them rather than pass them off as links.
DELETE FROM user_sessions;
DELETE FROM request_tokens;
ALTER TABLE request_tokens RENAME COLUMN token_hash TO token;
-- +goose StatementEnd

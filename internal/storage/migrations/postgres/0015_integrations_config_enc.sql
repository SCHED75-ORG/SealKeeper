-- +goose Up
-- +goose StatementBegin
-- Integration credentials (bearer tokens, Splunk HEC token, Sentinel shared
-- key, basic-auth password, Elastic API key) move out of the clear
-- config_json column into an AES-256-GCM blob sealed by cryptobox under
-- AAD sha256("sealkeeper-integration:<id>"). Existing rows are sealed at
-- boot by integrations.Repo.SealLegacyConfigs, which then blanks
-- config_json to '{}'.
ALTER TABLE integrations ADD COLUMN config_enc BYTEA;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE integrations DROP COLUMN config_enc;
-- +goose StatementEnd

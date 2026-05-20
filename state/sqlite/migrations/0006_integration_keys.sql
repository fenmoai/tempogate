CREATE TABLE integration_keys (
    id          TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    role        TEXT NOT NULL,
    owner       TEXT NOT NULL,
    jti         TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL,
    expires_at  TIMESTAMP,
    revoked_at  TIMESTAMP
);

CREATE INDEX idx_integration_keys_owner     ON integration_keys(owner);
CREATE INDEX idx_integration_keys_namespace ON integration_keys(namespace);
CREATE INDEX idx_integration_keys_id_desc   ON integration_keys(id DESC);

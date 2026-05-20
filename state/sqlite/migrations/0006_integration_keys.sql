CREATE TABLE integration_keys (
    id          TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    -- Matches the Role enum in package admin, which is also the canonical
    -- vocabulary the Temporal default ClaimMapper's permissionToRole() reads
    -- from a "<namespace>:<role>" permissions entry. Keeping the constraint
    -- in lock-step with the enum means a code-level mistake (e.g. a future
    -- migration writing a misspelled role) is caught at insert time instead
    -- of silently producing a token that Temporal will reject as RoleUndefined.
    role        TEXT NOT NULL CHECK (role IN ('read', 'write', 'worker', 'admin')),
    owner       TEXT NOT NULL,
    jti         TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL,
    expires_at  TIMESTAMP,
    revoked_at  TIMESTAMP
);

CREATE INDEX idx_integration_keys_owner     ON integration_keys(owner);
CREATE INDEX idx_integration_keys_namespace ON integration_keys(namespace);
CREATE INDEX idx_integration_keys_id_desc   ON integration_keys(id DESC);

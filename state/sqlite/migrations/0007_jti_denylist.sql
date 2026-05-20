CREATE TABLE jti_denylist (
    jti        TEXT PRIMARY KEY,
    revoked_at TIMESTAMP NOT NULL
);

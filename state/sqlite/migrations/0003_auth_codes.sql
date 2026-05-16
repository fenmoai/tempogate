CREATE TABLE auth_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    email                 TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    created_at            TIMESTAMP NOT NULL,
    expires_at            TIMESTAMP NOT NULL
);

CREATE INDEX idx_auth_codes_expires_at ON auth_codes(expires_at);

CREATE TABLE auth_requests (
    internal_state        TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    client_state          TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    created_at            TIMESTAMP NOT NULL,
    expires_at            TIMESTAMP NOT NULL
);

CREATE INDEX idx_auth_requests_expires_at ON auth_requests(expires_at);

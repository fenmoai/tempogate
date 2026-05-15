CREATE TABLE keypairs (
    kid         TEXT PRIMARY KEY,
    alg         TEXT NOT NULL,
    private_pem BLOB NOT NULL,
    public_pem  BLOB NOT NULL,
    created_at  TIMESTAMP NOT NULL
);

CREATE INDEX idx_keypairs_created_at ON keypairs(created_at);

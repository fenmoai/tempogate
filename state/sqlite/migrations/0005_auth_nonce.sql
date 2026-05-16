-- OIDC Core §2: a relying party that sends `nonce` at /authorize must get it
-- echoed in the ID token. nonce is carried from the pending auth request
-- through the minted auth code so /token can stamp it. Existing rows (none in
-- practice — both tables are short-lived) default to '' (no nonce requested).
ALTER TABLE auth_requests ADD COLUMN nonce TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_codes ADD COLUMN nonce TEXT NOT NULL DEFAULT '';

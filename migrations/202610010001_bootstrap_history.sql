-- A consumed bootstrap challenge is marked, not deleted, so issuance and
-- enrollment quotas keep counting it. The API sweeper prunes challenge history
-- after two days and replay nonces once they expire.
ALTER TABLE bootstrap_challenges ADD COLUMN consumed_at TIMESTAMPTZ;
CREATE INDEX bootstrap_challenge_created ON bootstrap_challenges(created_at);
CREATE INDEX used_nonce_expiry ON used_nonces(expires_at);

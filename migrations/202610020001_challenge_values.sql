-- DNS-01 challenges become a desired set of TXT values per installation,
-- with no client-chosen lease identities (bloom-relay wire v1 is unreleased).
-- A value lives for five minutes and is refreshed by the client while it
-- validates. `revision` changes whenever the set's membership changes; the
-- challenge worker records `ready_revision` only after it has published and
-- observed exactly that revision.
-- Lock first so the scan sees every lease. Then queue one reconciliation per
-- installation that had a lease: with an empty set it removes their old TXT
-- records. A previous-release job cannot write after it: all DNS jobs hold the
-- installation's advisory lock and old jobs read challenge_leases under it.
LOCK TABLE challenge_leases IN ACCESS EXCLUSIVE MODE;
INSERT INTO outbox(installation_id, kind, payload)
  SELECT DISTINCT installation_id, 'reconcile_txt', '{}'::jsonb FROM challenge_leases;
UPDATE outbox SET completed_at = now()
  WHERE kind IN ('publish_txt', 'remove_txt') AND completed_at IS NULL;
DROP TABLE challenge_leases;

CREATE TABLE challenge_values (
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  txt_value TEXT NOT NULL CHECK (txt_value ~ '^[A-Za-z0-9_-]{43}$'),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (installation_id, txt_value)
);
CREATE INDEX challenge_values_expiry ON challenge_values(expires_at);

CREATE TABLE challenge_state (
  installation_id UUID PRIMARY KEY REFERENCES installations(installation_id),
  revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
  ready_revision BIGINT
);

-- Deploys migrate as the schema owner but do not reapply runtime grants, so
-- the new tables carry their own (roles exist only on provisioned hosts).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bloom-relay-api') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON challenge_values, challenge_state
      TO "bloom-relay-api";
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bloom-relay-dns-challenge') THEN
    GRANT SELECT ON challenge_values, challenge_state TO "bloom-relay-dns-challenge";
    GRANT UPDATE (ready_revision) ON challenge_state TO "bloom-relay-dns-challenge";
  END IF;
END
$$;

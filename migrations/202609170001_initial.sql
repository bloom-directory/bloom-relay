CREATE TABLE installations (
  installation_id UUID PRIMARY KEY,
  hostname TEXT NOT NULL UNIQUE,
  admin_public_key BYTEA NOT NULL CHECK (octet_length(admin_public_key) = 32),
  placement TEXT NOT NULL,
  generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
  state TEXT NOT NULL CHECK (state IN ('pending_dns', 'dns_ready', 'retired')),
  acme_account_uri TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at TIMESTAMPTZ
);
CREATE TABLE hostname_reservations (
  hostname TEXT PRIMARY KEY,
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  reserved_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE operations (
  operation_id UUID PRIMARY KEY,
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  kind TEXT NOT NULL,
  request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
  result JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE used_nonces (
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  nonce TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (installation_id, nonce)
);
CREATE TABLE bootstrap_challenges (
  nonce TEXT PRIMARY KEY,
  source_ip INET NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX bootstrap_challenge_source ON bootstrap_challenges(source_ip, created_at);
CREATE TABLE scoped_credentials (
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  scope TEXT NOT NULL CHECK (scope IN ('surface_admin', 'tunnel', 'dns_challenge')),
  generation BIGINT NOT NULL CHECK (generation > 0),
  public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY (installation_id, scope, generation)
);
CREATE TABLE scoped_bearer_credentials (
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  scope TEXT NOT NULL CHECK (scope IN ('tunnel', 'dns_challenge')),
  generation BIGINT NOT NULL CHECK (generation > 0),
  token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY (installation_id, scope, generation)
);
CREATE TABLE tunnel_leases (
  installation_id UUID PRIMARY KEY REFERENCES installations(installation_id),
  generation BIGINT NOT NULL,
  gateway_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE challenge_leases (
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  lease_id UUID NOT NULL,
  txt_value TEXT NOT NULL,
  generation BIGINT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  dns_ready_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ,
  PRIMARY KEY (installation_id, lease_id)
);
CREATE TABLE certificate_inventory (
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  fingerprint TEXT NOT NULL,
  lineage TEXT NOT NULL,
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (installation_id, fingerprint)
);
CREATE TABLE outbox (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  kind TEXT NOT NULL,
  payload JSONB NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);
CREATE INDEX outbox_pending ON outbox(next_attempt_at) WHERE completed_at IS NULL;
CREATE TABLE security_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  installation_id UUID NOT NULL REFERENCES installations(installation_id),
  operation_id UUID,
  event TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE restore_fence (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  revision BIGINT NOT NULL CHECK (revision > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO restore_fence(singleton, revision) VALUES (TRUE, 1);

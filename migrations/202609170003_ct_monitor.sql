CREATE TABLE ct_feed_checkpoints (
  source TEXT PRIMARY KEY,
  position BIGINT NOT NULL CHECK (position >= 0),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE ct_observations (
  source TEXT NOT NULL REFERENCES ct_feed_checkpoints(source),
  position BIGINT NOT NULL,
  installation_id UUID REFERENCES installations(installation_id),
  hostname TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expected BOOLEAN NOT NULL,
  PRIMARY KEY (source, position)
);
CREATE TABLE ct_alerts (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  source TEXT NOT NULL,
  position BIGINT NOT NULL,
  installation_id UUID REFERENCES installations(installation_id),
  hostname TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged_at TIMESTAMPTZ,
  UNIQUE (source, position)
);

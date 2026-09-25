ALTER TABLE ct_alerts ADD COLUMN delivered_at TIMESTAMPTZ;
CREATE TABLE ct_health_alerts (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  source TEXT NOT NULL REFERENCES ct_feed_checkpoints(source),
  time_window BIGINT NOT NULL,
  lag_seconds BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ,
  UNIQUE (source, time_window)
);

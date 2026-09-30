-- Advance the restore fence when a transaction commits, after it holds every
-- other row lock it needs. Advancing it mid-transaction let two security
-- transitions deadlock (40P01): one held a row and waited for the fence row,
-- the other held the fence row and waited for that row. Deferred to commit,
-- a transaction holding the fence row waits for nothing else, so no cycle
-- can form. The revision still advances once per row, before commit.
DROP TRIGGER security_audit_restore_fence ON security_audit;
CREATE CONSTRAINT TRIGGER security_audit_restore_fence
AFTER INSERT ON security_audit
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION advance_restore_fence();

DROP TRIGGER ct_checkpoint_restore_fence ON ct_feed_checkpoints;
CREATE CONSTRAINT TRIGGER ct_checkpoint_restore_fence
AFTER INSERT OR UPDATE ON ct_feed_checkpoints
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION advance_restore_fence();

DROP TRIGGER ct_alert_restore_fence ON ct_alerts;
CREATE CONSTRAINT TRIGGER ct_alert_restore_fence
AFTER INSERT OR UPDATE ON ct_alerts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION advance_restore_fence();

DROP TRIGGER ct_health_alert_restore_fence ON ct_health_alerts;
CREATE CONSTRAINT TRIGGER ct_health_alert_restore_fence
AFTER INSERT OR UPDATE ON ct_health_alerts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION advance_restore_fence();

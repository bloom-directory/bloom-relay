CREATE TRIGGER ct_alert_restore_fence
AFTER INSERT OR UPDATE ON ct_alerts
FOR EACH ROW EXECUTE FUNCTION advance_restore_fence();

CREATE TRIGGER ct_health_alert_restore_fence
AFTER INSERT OR UPDATE ON ct_health_alerts
FOR EACH ROW EXECUTE FUNCTION advance_restore_fence();

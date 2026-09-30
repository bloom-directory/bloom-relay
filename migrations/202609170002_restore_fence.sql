CREATE FUNCTION advance_restore_fence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE restore_fence SET revision = revision + 1, updated_at = now() WHERE singleton = TRUE;
  RETURN NEW;
END;
$$;

CREATE TRIGGER security_audit_restore_fence
AFTER INSERT ON security_audit
FOR EACH ROW EXECUTE FUNCTION advance_restore_fence();

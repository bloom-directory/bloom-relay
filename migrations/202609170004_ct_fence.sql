CREATE TRIGGER ct_checkpoint_restore_fence
AFTER INSERT OR UPDATE ON ct_feed_checkpoints
FOR EACH ROW EXECUTE FUNCTION advance_restore_fence();

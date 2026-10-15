-- Keep consumed refresh rows until the absolute family deadline: they are replay evidence.
CREATE INDEX session_families_expiry_idx ON session_families (expires_at);
CREATE INDEX session_families_active_user_idx ON session_families (user_id) WHERE revoked_at IS NULL;

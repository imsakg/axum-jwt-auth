-- Fail rather than silently granting privileges to legacy/unknown role values.
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user','admin'));
ALTER TABLE users ADD CONSTRAINT users_email_normalized CHECK (email=LOWER(BTRIM(email)));
CREATE FUNCTION touch_user_updated_at() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at=NOW();
    RETURN NEW;
END;
$$;
CREATE TRIGGER users_touch_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION touch_user_updated_at();

DROP TRIGGER users_touch_updated_at ON users;
DROP FUNCTION touch_user_updated_at();
ALTER TABLE users DROP CONSTRAINT users_email_normalized;
ALTER TABLE users DROP CONSTRAINT users_role_check;

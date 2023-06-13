-- Baseline for new installations. An existing database with the original
-- 20240212214955 migration must be migrated deliberately; see operations docs.
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    photo TEXT NOT NULL DEFAULT 'default.png',
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    password TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

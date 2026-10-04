-- ============================================================
-- 0005_role_constraint.sql
-- Add owner to the users role constraint
-- ============================================================

PRAGMA foreign_keys = OFF;

-- ------------------------------------------------------------
-- 1. Create replacement users table
-- ------------------------------------------------------------

CREATE TABLE users_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT CHECK(role IN ('admin','owner','user','tenant')),
    name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    password_salt TEXT,
    created_at TEXT,
    requires_change_password INTEGER NOT NULL DEFAULT 0,
    temp_password_expiration DATETIME
);

-- ------------------------------------------------------------
-- 2. Copy existing users
-- ------------------------------------------------------------

INSERT INTO users_new (
    id,
    role,
    name,
    email,
    password_hash,
    password_salt,
    created_at,
    requires_change_password,
    temp_password_expiration
)
SELECT
    id,
    role,
    name,
    email,
    password_hash,
    password_salt,
    created_at,
    requires_change_password,
    temp_password_expiration
FROM users;

-- ------------------------------------------------------------
-- 3. Replace old table
-- ------------------------------------------------------------

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

-- ------------------------------------------------------------
-- 4. Restore useful indexes
-- ------------------------------------------------------------

CREATE UNIQUE INDEX IF NOT EXISTS
idx_users_email
ON users(email);

-- ------------------------------------------------------------
-- 5. Restore foreign-key enforcement
-- ------------------------------------------------------------

PRAGMA foreign_keys = ON;
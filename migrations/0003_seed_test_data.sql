-- ============================================================
-- 0003_seed_test_data.sql
-- Development / testing seed data
-- ============================================================

INSERT OR IGNORE INTO users (
  id,
  email,
  password_hash,
  password_salt,
  role,
  created_at,
  name,
  requires_change_password,
  temp_password_expiration
)
VALUES (
  1,
  'admin@example.com',
  'd92ab3717b7ad3bf6ccf593ebf11473f50231417a3aa80471164a39f8844b65f',
  '000102030405060708090a0b0c0d0e0f',
  'admin',
  '2026-09-16T15:00:00Z',
  'System Admin',
  0,
  NULL
);

INSERT OR IGNORE INTO signup_keys (
  id,
  code,
  used,
  user_id
)
VALUES (
  1,
  'admin-demo-key',
  0,
  NULL
);

INSERT OR IGNORE INTO houses (
  id,
  name,
  location,
  owner_id,
  created_at
)
VALUES (
  1,
  'Test Property',
  'Demo Street 100',
  1,
  '2026-09-16T15:00:00Z'
);

INSERT OR IGNORE INTO user_house_access (
  user_id,
  house_id,
  access_level,
  created_at
)
VALUES (
  1,
  1,
  'admin',
  '2026-09-16T15:00:00Z'
);

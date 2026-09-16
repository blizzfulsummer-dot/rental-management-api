-- Seed test data for development/testing

-- Create a signup key for admin registration
INSERT OR IGNORE INTO signup_keys (id, code, used, user_id)
VALUES (1, 'admin-demo-key', 0, NULL);

-- Create a test house for WebSocket testing
INSERT OR IGNORE INTO houses (id, name, location, owner_id, created_at)
VALUES (
  1,
  'Test Property',
  'Test Location',
  1,
  '2026-09-16T15:00:00Z'
);

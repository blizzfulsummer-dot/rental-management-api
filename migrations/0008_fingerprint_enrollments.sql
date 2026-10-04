CREATE TABLE IF NOT EXISTS device_fingerprint_enrollments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  fingerprint_id INTEGER NOT NULL CHECK (fingerprint_id BETWEEN 1 AND 127),
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
  enrollment_pending INTEGER NOT NULL DEFAULT 0 CHECK (enrollment_pending IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (device_id, user_id),
  UNIQUE (device_id, fingerprint_id),
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fingerprint_enrollments_device_status
  ON device_fingerprint_enrollments(device_id, status, enrollment_pending);

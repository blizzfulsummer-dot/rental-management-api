CREATE TABLE IF NOT EXISTS user_device_access (
  user_id INTEGER NOT NULL,
  device_id INTEGER NOT NULL,
  PRIMARY KEY (user_id, device_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

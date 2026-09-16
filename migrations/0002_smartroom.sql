-- MIGRATION: Add houses, devices, and permissions for smart-home system
-- Add this to your migrations/0002_smartroom.sql file

-- Houses table
CREATE TABLE IF NOT EXISTS houses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  location TEXT,
  owner_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(owner_id) REFERENCES users(id)
);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  house_id INTEGER NOT NULL,
  device_name TEXT NOT NULL,
  device_type TEXT NOT NULL,
  device_id_external TEXT,
  status TEXT DEFAULT 'offline',
  created_at TEXT NOT NULL,
  FOREIGN KEY(house_id) REFERENCES houses(id)
);

-- User-House permissions table
CREATE TABLE IF NOT EXISTS user_house_access (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  house_id INTEGER NOT NULL,
  access_level TEXT DEFAULT 'viewer',
  created_at TEXT NOT NULL,
  UNIQUE(user_id, house_id),
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(house_id) REFERENCES houses(id)
);

-- WebSocket tickets table (short-lived, single-use)
CREATE TABLE IF NOT EXISTS websocket_tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL,
  house_id INTEGER NOT NULL,
  client_type TEXT DEFAULT 'web',
  device_id INTEGER,
  expires_at TEXT NOT NULL,
  consumed INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(house_id) REFERENCES houses(id),
  FOREIGN KEY(device_id) REFERENCES devices(id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_houses_owner_id ON houses(owner_id);
CREATE INDEX IF NOT EXISTS idx_devices_house_id ON devices(house_id);
CREATE INDEX IF NOT EXISTS idx_user_house_access_user_id ON user_house_access(user_id);
CREATE INDEX IF NOT EXISTS idx_user_house_access_house_id ON user_house_access(house_id);
CREATE INDEX IF NOT EXISTS idx_websocket_tickets_ticket_id ON websocket_tickets(ticket_id);
CREATE INDEX IF NOT EXISTS idx_websocket_tickets_expires ON websocket_tickets(expires_at);

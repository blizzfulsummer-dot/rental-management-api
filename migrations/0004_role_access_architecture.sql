-- ============================================================
-- 0004_role_access_architecture.sql
-- ReMan Role & Access Architecture
-- ============================================================

-- ============================================================
-- 1. POPULATE HOUSE UID
-- ============================================================

UPDATE houses
SET house_uid = 'HSE-' || printf('%06d', id)
WHERE house_uid IS NULL
   OR house_uid = '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_houses_house_uid
ON houses(house_uid);


-- ============================================================
-- 2. TENANT -> ROOM INDEX
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_tenants_room_id
ON tenants(room_id);


-- ============================================================
-- 3. USER -> HOUSE ACCESS INDEX
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_user_house_access_user_house
ON user_house_access(user_id, house_id);


-- ============================================================
-- 4. NORMALIZE EXISTING TEST OWNER
-- ============================================================

UPDATE users
SET role = 'owner'
WHERE id = 1
  AND role IN ('user', 'owner');
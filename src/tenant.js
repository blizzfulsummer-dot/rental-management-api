import { parseJsonBody, validatePassword, validateTenantPayload, validateId, sanitizeString } from './lib/validation.js';
import { hashPBKDF2, verifyPBKDF2, arrayBufferToHex, hexToArrayBuffer } from './lib/crypto.js';

async function isTenantOwnedByUser(env, userId, tenantUserId) {
  const row = await env.DB
    .prepare(`
      SELECT 1
      FROM user_house_access uha
      JOIN houses h ON h.id = uha.house_id
      WHERE uha.user_id = ? AND h.owner_id = ?
      LIMIT 1
    `)
    .bind(tenantUserId, userId)
    .first();

  return Boolean(row);
}

async function isHouseOwnedByUser(env, userId, houseId) {
  const row = await env.DB
    .prepare('SELECT id FROM houses WHERE id = ? AND owner_id = ?')
    .bind(houseId, userId)
    .first();

  return Boolean(row);
}

export async function createTenant(request, env, authUser) {
  if (authUser.role !== 'admin' && authUser.role !== 'owner') {
    return json({ error: 'Forbidden' }, 403);
  }

  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const validation = validateTenantPayload(parsed.data);
  if (!validation.ok) return json({ error: 'Invalid tenant payload', details: validation.errors }, 400);

  const {
    user_id,
    balance,
    deposit,
    rent_amount,
    billing_cycle,
    leased_unit,
    onboard_date,
    house_id
  } = parsed.data;

  if (!user_id) {
    return json({ error: 'Missing required fields' }, 400);
  }

  try {
    if (authUser.role === 'owner') {
      if (!house_id) {
        return json({ error: 'house_id is required for owner-created tenants' }, 400);
      }

      const hasAccess = await isHouseOwnedByUser(env, authUser.id, house_id);
      if (!hasAccess) {
        return json({ error: 'Forbidden' }, 403);
      }
    }

    await env.DB
      .prepare(`
        INSERT INTO tenants
          (user_id, balance, deposit, rent_amount, billing_cycle, leased_unit, onboard_date, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        user_id,
        balance ?? 0,
        deposit ?? 0,
        rent_amount,
        billing_cycle ?? 'monthly',
        leased_unit,
        onboard_date,
        new Date().toISOString()
      )
      .run();

    if (authUser.role === 'owner' && house_id) {
      await env.DB
        .prepare(`
          INSERT OR IGNORE INTO user_house_access (user_id, house_id, access_level, created_at)
          VALUES (?, ?, ?, ?)
        `)
        .bind(user_id, house_id, 'tenant', new Date().toISOString())
        .run();
    }

    return json({ success: true });
  } catch (error) {
    console.error('Create tenant error:', error);
    return json({ error: 'Failed to create tenant' }, 500);
  }
}

export async function listTenants(request, env, authUser) {
  if (authUser.role !== 'admin' && authUser.role !== 'owner') {
    return json({ error: 'Forbidden' }, 403);
  }

  try {
    let rows;

    if (authUser.role === 'admin') {
      rows = await env.DB
        .prepare(`
          SELECT
            t.id,
            u.email,
            u.name,
            u.role,
            t.balance,
            t.rent_amount,
            t.leased_unit,
            t.onboard_date
          FROM tenants t
          JOIN users u ON u.id = t.user_id
          ORDER BY t.created_at DESC
        `)
        .all();
    } else {
      rows = await env.DB
        .prepare(`
          SELECT DISTINCT
            t.id,
            u.email,
            u.name,
            u.role,
            t.balance,
            t.rent_amount,
            t.leased_unit,
            t.onboard_date
          FROM tenants t
          JOIN users u ON u.id = t.user_id
          JOIN user_house_access uha ON uha.user_id = t.user_id
          JOIN houses h ON h.id = uha.house_id
          WHERE h.owner_id = ?
          ORDER BY t.created_at DESC
        `)
        .bind(authUser.id)
        .all();
    }

    return json({ tenants: rows.results });
  } catch (error) {
    console.error('List tenants error:', error);
    return json({ error: 'Failed to fetch tenants' }, 500);
  }
}

export async function getTenant(request, env, authUser, tenantId) {
  const idValidation = validateId(tenantId);
  if (!idValidation.ok) return json({ error: 'Invalid tenant ID' }, 400);

  try {
    const row = await env.DB
      .prepare(`
        SELECT t.*, u.email, u.name, u.role
        FROM tenants t
        JOIN users u ON u.id = t.user_id
        WHERE t.id = ?
      `)
      .bind(idValidation.value)
      .first();

    if (!row) return json({ error: 'Tenant not found' }, 404);

    const canAccess = authUser.role === 'admin' || row.user_id === authUser.id || (authUser.role === 'owner' && await isTenantOwnedByUser(env, authUser.id, row.user_id));
    if (!canAccess) {
      return json({ error: 'Forbidden' }, 403);
    }

    if (authUser.role === 'admin' || authUser.role === 'owner') {
      return json({ tenant: row });
    }

    return json({
      tenant: {
        id: row.id,
        user_id: row.user_id,
        email: row.email,
        name: row.name,
        role: row.role,
        leased_unit: row.leased_unit,
        onboard_date: row.onboard_date,
        billing_cycle: row.billing_cycle
      }
    });
  } catch (error) {
    console.error('Get tenant error:', error);
    return json({ error: 'Failed to fetch tenant' }, 500);
  }
}

export async function updateTenant(request, env, authUser, tenantId) {
  const idValidation = validateId(tenantId);
  if (!idValidation.ok) return json({ error: 'Invalid tenant ID' }, 400);

  try {
    const tenant = await env.DB
      .prepare('SELECT id, user_id FROM tenants WHERE id = ?')
      .bind(idValidation.value)
      .first();

    if (!tenant) return json({ error: 'Tenant not found' }, 404);

    const canManage = authUser.role === 'admin' || tenant.user_id === authUser.id || (authUser.role === 'owner' && await isTenantOwnedByUser(env, authUser.id, tenant.user_id));
    if (!canManage) {
      return json({ error: 'Forbidden' }, 403);
    }

    const parsed = await parseJsonBody(request);
    if (!parsed.ok) return json({ error: parsed.error }, 400);

    if (authUser.role === 'admin' || authUser.role === 'owner') {
      await env.DB
        .prepare(`
          UPDATE tenants SET
            balance = ?,
            deposit = ?,
            rent_amount = ?,
            billing_cycle = ?,
            leased_unit = ?
          WHERE id = ?
        `)
        .bind(
          parsed.data.balance,
          parsed.data.deposit,
          parsed.data.rent_amount,
          parsed.data.billing_cycle,
          parsed.data.leased_unit,
          idValidation.value
        )
        .run();

      return json({ success: true });
    }

    const currentPassword = parsed.data?.currentPassword ?? parsed.data?.oldPassword;
    const newPassword = parsed.data?.newPassword ?? parsed.data?.password;

    if (!currentPassword || !newPassword) {
      return json({ error: 'Missing password fields' }, 400);
    }

    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.ok) {
      return json({ error: 'Password is too weak' }, 400);
    }

    const userRow = await env.DB
      .prepare('SELECT id, password_hash, password_salt FROM users WHERE id = ?')
      .bind(tenant.user_id)
      .first();

    if (!userRow) return json({ error: 'User not found' }, 404);

    const valid = await verifyPBKDF2(userRow.password_hash, userRow.password_salt, currentPassword);
    if (!valid) return json({ error: 'Current password is incorrect' }, 401);

    const { hash: derivedBits, salt } = await hashPBKDF2(newPassword);
    await env.DB
      .prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
      .bind(arrayBufferToHex(derivedBits), arrayBufferToHex(salt), userRow.id)
      .run();

    return json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Update tenant error:', error);
    return json({ error: 'Failed to update tenant' }, 500);
  }
}

export async function deleteTenant(request, env, authUser, tenantId) {
  if (authUser.role !== 'admin' && authUser.role !== 'owner') {
    return json({ error: 'Forbidden' }, 403);
  }

  const idValidation = validateId(tenantId);
  if (!idValidation.ok) return json({ error: 'Invalid tenant ID' }, 400);

  try {
    const tenant = await env.DB
      .prepare('SELECT user_id FROM tenants WHERE id = ?')
      .bind(idValidation.value)
      .first();

    if (!tenant) return json({ error: 'Tenant not found' }, 404);

    if (authUser.role === 'owner') {
      const isOwner = await isTenantOwnedByUser(env, authUser.id, tenant.user_id);
      if (!isOwner) {
        return json({ error: 'Forbidden' }, 403);
      }
    }

    await env.DB
      .prepare('DELETE FROM tenants WHERE id = ?')
      .bind(idValidation.value)
      .run();

    await env.DB
      .prepare(`
        DELETE FROM user_house_access
        WHERE user_id = ?
          AND house_id IN (
            SELECT id FROM houses WHERE owner_id = ?
          )
      `)
      .bind(tenant.user_id, authUser.id)
      .run();

    return json({ success: true });
  } catch (error) {
    console.error('Delete tenant error:', error);
    return json({ error: 'Failed to delete tenant' }, 500);
  }
}

async function userHasHouseAccess(env, userId, houseId) {
  if (!userId || !houseId) return false;

  const directOwner = await env.DB
    .prepare('SELECT id FROM houses WHERE id = ? AND owner_id = ?')
    .bind(houseId, userId)
    .first();

  if (directOwner) return true;

  const accessRow = await env.DB
    .prepare('SELECT id FROM user_house_access WHERE user_id = ? AND house_id = ?')
    .bind(userId, houseId)
    .first();

  if (accessRow) return true;

  const tenantRow = await env.DB
    .prepare('SELECT t.id FROM tenants t JOIN user_house_access uha ON uha.house_id = ? WHERE t.user_id = ? AND uha.user_id = ? LIMIT 1')
    .bind(houseId, userId, userId)
    .first();

  return Boolean(tenantRow);
}

export async function listHouses(request, env, authUser) {
  try {
    const normalizeHouse = (house) => ({
      ...house,
      location: house.location ?? house.address ?? null
    });

    if (authUser.role === 'admin') {
      const rows = await env.DB
        .prepare(`
          SELECT h.*
          FROM houses h
          ORDER BY h.created_at DESC
        `)
        .all();
      return json({ houses: (rows.results || []).map(normalizeHouse) });
    }

    if (authUser.role === 'owner') {
      const rows = await env.DB
        .prepare(`
          SELECT h.*
          FROM houses h
          WHERE h.owner_id = ?
          ORDER BY h.created_at DESC
        `)
        .bind(authUser.id)
        .all();
      return json({ houses: (rows.results || []).map(normalizeHouse) });
    }

    const rows = await env.DB
      .prepare(`
        SELECT DISTINCT h.*
        FROM houses h
        LEFT JOIN user_house_access uha ON uha.house_id = h.id
        WHERE h.owner_id = ? OR uha.user_id = ?
        ORDER BY h.created_at DESC
      `)
      .bind(authUser.id, authUser.id)
      .all();

    return json({ houses: (rows.results || []).map(normalizeHouse) });
  } catch (error) {
    console.error('List houses error:', error);
    return json({ error: 'Failed to fetch houses' }, 500);
  }
}

export async function createHouse(request, env, authUser) {
  if (authUser.role !== 'admin' && authUser.role !== 'owner') {
    return json({ error: 'Forbidden' }, 403);
  }

  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const name = typeof parsed.data?.name === 'string' ? parsed.data.name.trim() : '';
  const location = typeof parsed.data?.location === 'string' ? parsed.data.location.trim() : null;

  if (!name) return json({ error: 'House name is required' }, 400);

  try {
    const ownerId = authUser.role === 'owner' ? authUser.id : Number(parsed.data?.owner_id ?? authUser.id);
    const houseUid = `HSE-${crypto.getRandomValues(new Uint8Array(5)).reduce((acc, byte) => acc + 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[byte % 26], '')}`;

    const result = await env.DB
      .prepare(`
        INSERT INTO houses (name, location, owner_id, house_uid, created_at)
        VALUES (?, ?, ?, ?, ?)
      `)
      .bind(name, location, ownerId, houseUid, new Date().toISOString())
      .run();

    const house = await env.DB
      .prepare('SELECT * FROM houses WHERE id = ?')
      .bind(result.meta?.last_row_id)
      .first();

    return json({ success: true, house }, 201);
  } catch (error) {
    console.error('Create house error:', error);
    return json({ error: 'Failed to create house' }, 500);
  }
}

export async function getHouse(request, env, authUser, houseId) {
  const idValidation = validateId(houseId);
  if (!idValidation.ok) return json({ error: 'Invalid house ID' }, 400);

  try {
    const row = await env.DB
      .prepare('SELECT * FROM houses WHERE id = ?')
      .bind(idValidation.value)
      .first();

    if (!row) return json({ error: 'House not found' }, 404);

    const canAccess = authUser.role === 'admin' || row.owner_id === authUser.id || await userHasHouseAccess(env, authUser.id, row.id);
    if (!canAccess) return json({ error: 'Forbidden' }, 403);

    return json({ house: row });
  } catch (error) {
    console.error('Get house error:', error);
    return json({ error: 'Failed to fetch house' }, 500);
  }
}

export async function updateHouse(request, env, authUser, houseId) {
  const idValidation = validateId(houseId);
  if (!idValidation.ok) return json({ error: 'Invalid house ID' }, 400);

  try {
    const house = await env.DB
      .prepare('SELECT * FROM houses WHERE id = ?')
      .bind(idValidation.value)
      .first();

    if (!house) return json({ error: 'House not found' }, 404);
    if (authUser.role !== 'admin' && house.owner_id !== authUser.id) return json({ error: 'Forbidden' }, 403);

    const parsed = await parseJsonBody(request);
    if (!parsed.ok) return json({ error: parsed.error }, 400);

    const name = typeof parsed.data?.name === 'string' ? parsed.data.name.trim() : house.name;
    const location = typeof parsed.data?.location === 'string' ? parsed.data.location.trim() : house.location;

    await env.DB
      .prepare('UPDATE houses SET name = ?, location = ? WHERE id = ?')
      .bind(name, location, idValidation.value)
      .run();

    return json({ success: true });
  } catch (error) {
    console.error('Update house error:', error);
    return json({ error: 'Failed to update house' }, 500);
  }
}

export async function deleteHouse(request, env, authUser, houseId) {
  const idValidation = validateId(houseId);
  if (!idValidation.ok) return json({ error: 'Invalid house ID' }, 400);

  try {
    const house = await env.DB
      .prepare('SELECT * FROM houses WHERE id = ?')
      .bind(idValidation.value)
      .first();

    if (!house) return json({ error: 'House not found' }, 404);
    if (authUser.role !== 'admin' && house.owner_id !== authUser.id) return json({ error: 'Forbidden' }, 403);

    await env.DB.prepare('DELETE FROM devices WHERE house_id = ?').bind(idValidation.value).run();
    await env.DB.prepare('DELETE FROM user_house_access WHERE house_id = ?').bind(idValidation.value).run();
    await env.DB.prepare('DELETE FROM houses WHERE id = ?').bind(idValidation.value).run();

    return json({ success: true });
  } catch (error) {
    console.error('Delete house error:', error);
    return json({ error: 'Failed to delete house' }, 500);
  }
}

export async function listHouseDevices(request, env, authUser, houseId) {
  const idValidation = validateId(houseId);
  if (!idValidation.ok) return json({ error: 'Invalid house ID' }, 400);

  const canAccess = authUser.role === 'admin' || await userHasHouseAccess(env, authUser.id, idValidation.value);
  if (!canAccess) return json({ error: 'Forbidden' }, 403);

  try {
    const rows = await env.DB
      .prepare('SELECT * FROM devices WHERE house_id = ? ORDER BY created_at DESC')
      .bind(idValidation.value)
      .all();

    return json({ devices: rows.results || [] });
  } catch (error) {
    console.error('List devices error:', error);
    return json({ error: 'Failed to fetch devices' }, 500);
  }
}

export async function createDevice(request, env, authUser) {
  if (authUser.role !== 'admin' && authUser.role !== 'owner') {
    return json({ error: 'Forbidden' }, 403);
  }

  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const houseId = parsed.data?.house_id;
  if (!houseId) return json({ error: 'house_id is required' }, 400);

  const idValidation = validateId(houseId);
  if (!idValidation.ok) return json({ error: 'Invalid house ID' }, 400);

  const canManage = authUser.role === 'admin' || await userHasHouseAccess(env, authUser.id, idValidation.value);
  if (!canManage) return json({ error: 'Forbidden' }, 403);

  const deviceName = typeof parsed.data?.device_name === 'string' ? parsed.data.device_name.trim() : '';
  const deviceType = typeof parsed.data?.device_type === 'string' ? parsed.data.device_type.trim() : 'sensor';

  if (!deviceName) return json({ error: 'device_name is required' }, 400);

  try {
    const result = await env.DB
      .prepare(`
        INSERT INTO devices (house_id, device_name, device_type, device_id_external, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .bind(idValidation.value, deviceName, deviceType, parsed.data?.device_id_external || null, parsed.data?.status || 'offline', new Date().toISOString())
      .run();

    const device = await env.DB
      .prepare('SELECT * FROM devices WHERE id = ?')
      .bind(result.meta?.last_row_id)
      .first();

    return json({ success: true, device }, 201);
  } catch (error) {
    console.error('Create device error:', error);
    return json({ error: 'Failed to create device' }, 500);
  }
}

export async function getDevice(request, env, authUser, deviceId) {
  const idValidation = validateId(deviceId);
  if (!idValidation.ok) return json({ error: 'Invalid device ID' }, 400);

  try {
    const row = await env.DB
      .prepare('SELECT * FROM devices WHERE id = ?')
      .bind(idValidation.value)
      .first();

    if (!row) return json({ error: 'Device not found' }, 404);

    const canAccess = authUser.role === 'admin' || await userHasHouseAccess(env, authUser.id, row.house_id);
    if (!canAccess) return json({ error: 'Forbidden' }, 403);

    return json({ device: row });
  } catch (error) {
    console.error('Get device error:', error);
    return json({ error: 'Failed to fetch device' }, 500);
  }
}

export async function updateDevice(request, env, authUser, deviceId) {
  const idValidation = validateId(deviceId);
  if (!idValidation.ok) return json({ error: 'Invalid device ID' }, 400);

  try {
    const device = await env.DB
      .prepare('SELECT * FROM devices WHERE id = ?')
      .bind(idValidation.value)
      .first();

    if (!device) return json({ error: 'Device not found' }, 404);
    const canManage = authUser.role === 'admin' || await userHasHouseAccess(env, authUser.id, device.house_id);
    if (!canManage) return json({ error: 'Forbidden' }, 403);

    const parsed = await parseJsonBody(request);
    if (!parsed.ok) return json({ error: parsed.error }, 400);

    const deviceName = typeof parsed.data?.device_name === 'string' ? parsed.data.device_name.trim() : device.device_name;
    const deviceType = typeof parsed.data?.device_type === 'string' ? parsed.data.device_type.trim() : device.device_type;
    const status = typeof parsed.data?.status === 'string' ? parsed.data.status : device.status;

    await env.DB
      .prepare('UPDATE devices SET device_name = ?, device_type = ?, status = ? WHERE id = ?')
      .bind(deviceName, deviceType, status, idValidation.value)
      .run();

    return json({ success: true });
  } catch (error) {
    console.error('Update device error:', error);
    return json({ error: 'Failed to update device' }, 500);
  }
}

export async function deleteDevice(request, env, authUser, deviceId) {
  const idValidation = validateId(deviceId);
  if (!idValidation.ok) return json({ error: 'Invalid device ID' }, 400);

  try {
    const device = await env.DB
      .prepare('SELECT * FROM devices WHERE id = ?')
      .bind(idValidation.value)
      .first();

    if (!device) return json({ error: 'Device not found' }, 404);
    const canManage = authUser.role === 'admin' || await userHasHouseAccess(env, authUser.id, device.house_id);
    if (!canManage) return json({ error: 'Forbidden' }, 403);

    await env.DB.prepare('DELETE FROM devices WHERE id = ?').bind(idValidation.value).run();
    return json({ success: true });
  } catch (error) {
    console.error('Delete device error:', error);
    return json({ error: 'Failed to delete device' }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

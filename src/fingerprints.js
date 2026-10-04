import { parseJsonBody, validateId } from './lib/validation.js';

async function getDevice(env, deviceId) {
  return env.DB.prepare(`
    SELECT d.id, d.house_id, h.owner_id
    FROM devices d
    JOIN houses h ON h.id = d.house_id
    WHERE d.id = ?
  `).bind(deviceId).first();
}

async function canAccessDevice(env, authUser, device) {
  if (authUser.role === 'admin') return true;
  if (authUser.role === 'owner' && Number(device.owner_id) === Number(authUser.id)) return true;
  const access = await env.DB
    .prepare('SELECT 1 FROM user_device_access WHERE user_id = ? AND device_id = ?')
    .bind(authUser.id, device.id)
    .first();
  return Boolean(access);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function listFingerprintEnrollments(env, authUser, deviceId) {
  const idValidation = validateId(deviceId);
  if (!idValidation.ok) return json({ error: 'Invalid device ID' }, 400);

  try {
    const device = await getDevice(env, idValidation.value);
    if (!device) return json({ error: 'Device not found' }, 404);
    if (!(await canAccessDevice(env, authUser, device))) return json({ error: 'Forbidden' }, 403);

    const isManager = authUser.role === 'admin'
      || (authUser.role === 'owner' && Number(device.owner_id) === Number(authUser.id));
    const rows = await env.DB.prepare(`
      SELECT e.fingerprint_id, e.user_id, u.name, u.email, e.status,
             e.enrollment_pending, e.created_at, e.updated_at
      FROM device_fingerprint_enrollments e
      JOIN users u ON u.id = e.user_id
      WHERE e.device_id = ? ${isManager ? '' : 'AND e.user_id = ?'}
      ORDER BY e.fingerprint_id
    `).bind(...(isManager ? [device.id] : [device.id, authUser.id])).all();

    return json({ enrollments: rows.results || [] });
  } catch (error) {
    console.error('List fingerprint enrollments error:', error);
    return json({ error: 'Failed to load fingerprint enrollments' }, 500);
  }
}

export async function startFingerprintEnrollment(env, authUser, deviceId) {
  const idValidation = validateId(deviceId);
  if (!idValidation.ok) return json({ error: 'Invalid device ID' }, 400);

  try {
    const device = await getDevice(env, idValidation.value);
    if (!device) return json({ error: 'Device not found' }, 404);
    if (!(await canAccessDevice(env, authUser, device))) return json({ error: 'Forbidden' }, 403);

    const current = await env.DB
      .prepare('SELECT fingerprint_id, status, enrollment_pending FROM device_fingerprint_enrollments WHERE device_id = ? AND user_id = ?')
      .bind(device.id, authUser.id)
      .first();
    if (current?.enrollment_pending) return json({ error: 'Fingerprint enrollment is already in progress' }, 409);

    let fingerprintId;
    if (current) {
      fingerprintId = current.fingerprint_id;
      await env.DB.prepare(`
        UPDATE device_fingerprint_enrollments
        SET status = CASE WHEN status = 'disabled' THEN 'pending' ELSE status END,
            enrollment_pending = 1, updated_at = ?
        WHERE device_id = ? AND user_id = ?
      `).bind(new Date().toISOString(), device.id, authUser.id).run();
    } else {
      const available = await env.DB.prepare(`
        WITH RECURSIVE ids(value) AS (
          SELECT 1
          UNION ALL SELECT value + 1 FROM ids WHERE value < 127
        )
        SELECT ids.value AS fingerprint_id
        FROM ids
        WHERE NOT EXISTS (
          SELECT 1 FROM device_fingerprint_enrollments e
          WHERE e.device_id = ? AND e.fingerprint_id = ids.value
            AND e.status != 'disabled'
        )
        ORDER BY ids.value
        LIMIT 1
      `).bind(device.id).first();
      if (!available) return json({ error: 'No fingerprint slots are available on this device' }, 409);
      fingerprintId = available.fingerprint_id;
      await env.DB.prepare('DELETE FROM device_fingerprint_enrollments WHERE device_id = ? AND fingerprint_id = ? AND status = ?')
        .bind(device.id, fingerprintId, 'disabled')
        .run();
      const now = new Date().toISOString();
      await env.DB.prepare(`
        INSERT INTO device_fingerprint_enrollments
          (device_id, user_id, fingerprint_id, status, enrollment_pending, created_at, updated_at)
        VALUES (?, ?, ?, 'pending', 1, ?, ?)
      `).bind(device.id, authUser.id, fingerprintId, now, now).run();
    }

    return json({
      success: true,
      deviceId: device.id,
      houseId: device.house_id,
      fingerprintId,
      replacing: Boolean(current)
    }, 201);
  } catch (error) {
    console.error('Start fingerprint enrollment error:', error);
    return json({ error: 'Failed to reserve a fingerprint slot' }, 500);
  }
}

export async function cancelFingerprintEnrollment(env, authUser, deviceId) {
  const idValidation = validateId(deviceId);
  if (!idValidation.ok) return json({ error: 'Invalid device ID' }, 400);

  try {
    const device = await getDevice(env, idValidation.value);
    if (!device) return json({ error: 'Device not found' }, 404);
    if (!(await canAccessDevice(env, authUser, device))) return json({ error: 'Forbidden' }, 403);

    await env.DB.prepare(`
      DELETE FROM device_fingerprint_enrollments
      WHERE device_id = ? AND user_id = ? AND status = 'pending' AND enrollment_pending = 1
    `).bind(device.id, authUser.id).run();
    await env.DB.prepare(`
      UPDATE device_fingerprint_enrollments
      SET enrollment_pending = 0, updated_at = ?
      WHERE device_id = ? AND user_id = ? AND status != 'pending' AND enrollment_pending = 1
    `).bind(new Date().toISOString(), device.id, authUser.id).run();
    return json({ success: true });
  } catch (error) {
    console.error('Cancel fingerprint enrollment error:', error);
    return json({ error: 'Failed to cancel fingerprint enrollment' }, 500);
  }
}

export async function removeFingerprintEnrollment(request, env, authUser, deviceId, fingerprintId) {
  if (authUser.role !== 'admin' && authUser.role !== 'owner') return json({ error: 'Forbidden' }, 403);
  const deviceValidation = validateId(deviceId);
  const fingerprintValidation = validateId(fingerprintId);
  if (!deviceValidation.ok || !fingerprintValidation.ok || fingerprintValidation.value > 127) {
    return json({ error: 'Invalid device or fingerprint ID' }, 400);
  }

  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);
  const action = parsed.data?.action;
  if (!['disable', 'delete'].includes(action)) return json({ error: 'Action must be disable or delete' }, 400);

  try {
    const device = await getDevice(env, deviceValidation.value);
    if (!device) return json({ error: 'Device not found' }, 404);
    if (authUser.role === 'owner' && Number(device.owner_id) !== Number(authUser.id)) {
      return json({ error: 'Forbidden' }, 403);
    }
    if (!(await canAccessDevice(env, authUser, device))) return json({ error: 'Forbidden' }, 403);

    const enrollment = await env.DB.prepare(`
      SELECT fingerprint_id FROM device_fingerprint_enrollments
      WHERE device_id = ? AND fingerprint_id = ?
    `).bind(device.id, fingerprintValidation.value).first();
    if (!enrollment) return json({ error: 'Fingerprint enrollment not found' }, 404);

    if (action === 'disable') {
      await env.DB.prepare(`
        UPDATE device_fingerprint_enrollments
        SET status = 'disabled', enrollment_pending = 0, updated_at = ?
        WHERE device_id = ? AND fingerprint_id = ?
      `).bind(new Date().toISOString(), device.id, fingerprintValidation.value).run();
    } else {
      await env.DB.prepare('DELETE FROM device_fingerprint_enrollments WHERE device_id = ? AND fingerprint_id = ?')
        .bind(device.id, fingerprintValidation.value).run();
    }

    return json({ success: true, action });
  } catch (error) {
    console.error('Remove fingerprint enrollment error:', error);
    return json({ error: 'Failed to remove fingerprint enrollment' }, 500);
  }
}

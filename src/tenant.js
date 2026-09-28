import { parseJsonBody, validatePassword, validateTenantPayload, validateId, sanitizeString } from './lib/validation.js';
import { hashPBKDF2, verifyPBKDF2, arrayBufferToHex, hexToArrayBuffer } from './lib/crypto.js';

export async function createTenant(request, env, authUser) {
  if (authUser.role !== 'admin') {
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
    onboard_date
  } = parsed.data;

  if (!user_id) {
    return json({ error: 'Missing required fields' }, 400);
  }

  try {
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

    return json({ success: true });
  } catch (error) {
    console.error('Create tenant error:', error);
    return json({ error: 'Failed to create tenant' }, 500);
  }
}

export async function listTenants(request, env, authUser) {
  if (authUser.role !== 'admin') {
    return json({ error: 'Forbidden' }, 403);
  }

  try {
    const rows = await env.DB
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

    if (authUser.role !== 'admin' && row.user_id !== authUser.id) {
      return json({ error: 'Forbidden' }, 403);
    }

    if (authUser.role === 'admin') {
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

    if (authUser.role !== 'admin' && tenant.user_id !== authUser.id) {
      return json({ error: 'Forbidden' }, 403);
    }

    const parsed = await parseJsonBody(request);
    if (!parsed.ok) return json({ error: parsed.error }, 400);

    if (authUser.role === 'admin') {
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
  if (authUser.role !== 'admin') {
    return json({ error: 'Forbidden' }, 403);
  }

  const idValidation = validateId(tenantId);
  if (!idValidation.ok) return json({ error: 'Invalid tenant ID' }, 400);

  try {
    await env.DB
      .prepare('DELETE FROM tenants WHERE id = ?')
      .bind(idValidation.value)
      .run();

    return json({ success: true });
  } catch (error) {
    console.error('Delete tenant error:', error);
    return json({ error: 'Failed to delete tenant' }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}



function generateHouseUid() {
    const bytes = crypto.getRandomValues(new Uint8Array(5));

    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    let code = "";

    for (const byte of bytes) {
        code += chars[byte % chars.length];
    }

    return `HSE-${code}`;
}

app.post("/api/houses", async (c) => {
    try {
        const user = await getAuthUser(c.req.raw, c.env);

        if (!user) {
            return c.json(
                {
                    success: false,
                    message: "Unauthorized"
                },
                401
            );
        }

        // For now, only admins can create houses.
        if (user.role !== "admin") {
            return c.json(
                {
                    success: false,
                    message: "Only administrators can create houses"
                },
                403
            );
        }

        const body = await c.req.json();

        const name = typeof body.name === "string"
            ? body.name.trim()
            : "";

        const address = typeof body.address === "string"
            ? body.address.trim()
            : null;

        if (!name) {
            return c.json(
                {
                    success: false,
                    message: "House name is required"
                },
                400
            );
        }

        let houseUid;
        let existing;

        // Generate a unique external house UID.
        do {
            houseUid = generateHouseUid();

            existing = await c.env.DB
                .prepare(`
                    SELECT id
                    FROM houses
                    WHERE house_uid = ?
                    LIMIT 1
                `)
                .bind(houseUid)
                .first();

        } while (existing);

        const result = await c.env.DB
            .prepare(`
                INSERT INTO houses (
                    name,
                    address,
                    owner_id,
                    house_uid
                )
                VALUES (?, ?, ?, ?)
            `)
            .bind(
                name,
                address,
                user.id,
                houseUid
            )
            .run();

        const house = await c.env.DB
            .prepare(`
                SELECT
                    id,
                    house_uid,
                    name,
                    address,
                    owner_id,
                    created_at
                FROM houses
                WHERE id = ?
            `)
            .bind(result.meta.last_row_id)
            .first();

        return c.json(
            {
                success: true,
                house
            },
            201
        );

    } catch (error) {
        console.error("[HOUSE CREATE ERROR]", error);

        return c.json(
            {
                success: false,
                message: "Failed to create house"
            },
            500
        );
    }
});

app.get("/api/houses", async (c) => {
    try {
        const user = await getAuthUser(c.req.raw, c.env);

        if (!user) {
            return c.json(
                {
                    success: false,
                    message: "Unauthorized"
                },
                401
            );
        }

        // ========================================================
        // ADMIN
        // ========================================================

        if (user.role === "admin") {
            const result = await c.env.DB
                .prepare(`
                    SELECT
                        id,
                        house_uid,
                        name,
                        address,
                        owner_id,
                        rent_amount,
                        date_occupied,
                        created_at
                    FROM houses
                    ORDER BY id DESC
                `)
                .all();

            return c.json({
                success: true,
                houses: result.results || []
            });
        }

        // ========================================================
        // TENANT
        // ========================================================

        if (user.role === "tenant") {
            const result = await c.env.DB
                .prepare(`
                    SELECT
                        h.id,
                        h.house_uid,
                        h.name,
                        h.address,
                        r.id AS room_id,
                        r.name AS room_name,
                        r.rent_amount,
                        r.date_occupied
                    FROM tenants t
                    INNER JOIN rooms r
                        ON r.id = t.room_id
                    INNER JOIN houses h
                        ON h.id = r.house_id
                    WHERE t.user_id = ?
                    ORDER BY h.id DESC
                `)
                .bind(user.id)
                .all();

            return c.json({
                success: true,
                houses: result.results || []
            });
        }

        // ========================================================
        // USER
        // ========================================================

        if (user.role === "user") {
            const result = await c.env.DB
                .prepare(`
                    SELECT
                        h.id,
                        h.house_uid,
                        h.name,
                        h.address,
                        h.owner_id,
                        h.created_at
                    FROM houses h
                    WHERE h.owner_id = ?
                    ORDER BY h.id DESC
                `)
                .bind(user.id)
                .all();

            return c.json({
                success: true,
                houses: result.results || []
            });
        }

        return c.json(
            {
                success: false,
                message: "Invalid user role"
            },
            403
        );

    } catch (error) {
        console.error("[HOUSE LIST ERROR]", error);

        return c.json(
            {
                success: false,
                message: "Failed to retrieve houses"
            },
            500
        );
    }
});
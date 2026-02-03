// tenant.js

export async function createTenant(request, env, authUser) {
  if (authUser.role !== 'admin') {
    return json({ error: 'Forbidden' }, 403);
  }

  const {
    user_id,
    balance,
    deposit,
    rent_amount,
    billing_cycle,
    leased_unit,
    onboard_date
  } = await request.json();

  if (!user_id || !rent_amount || !leased_unit || !onboard_date) {
    return json({ error: 'Missing required fields' }, 400);
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

  return json({ success: true });
}

export async function listTenants(request, env, authUser) {
  if (authUser.role !== 'admin') {
    return json({ error: 'Forbidden' }, 403);
  }

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
}

export async function getTenant(request, env, authUser, tenantId) {
  const row = await env.DB
    .prepare(`
      SELECT *
      FROM tenants
      WHERE id = ?
    `)
    .bind(tenantId)
    .first();

  if (!row) return json({ error: 'Tenant not found' }, 404);

  // tenant can only see own record
  if (authUser.role !== 'admin' && row.user_id !== authUser.id) {
    return json({ error: 'Forbidden' }, 403);
  }

  return json({ tenant: row });
}

export async function updateTenant(request, env, authUser, tenantId) {
  if (authUser.role !== 'admin') {
    return json({ error: 'Forbidden' }, 403);
  }

  const data = await request.json();

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
      data.balance,
      data.deposit,
      data.rent_amount,
      data.billing_cycle,
      data.leased_unit,
      tenantId
    )
    .run();

  return json({ success: true });
}

export async function deleteTenant(request, env, authUser, tenantId) {
  if (authUser.role !== 'admin') {
    return json({ error: 'Forbidden' }, 403);
  }

  await env.DB
    .prepare('DELETE FROM tenants WHERE id = ?')
    .bind(tenantId)
    .run();

  return json({ success: true });
}

/* ---------- helper ---------- */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

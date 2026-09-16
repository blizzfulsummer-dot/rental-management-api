import { SignJWT, jwtVerify } from 'jose';
import { parseJsonBody, validateEmail, validateLoginPayload, validatePassword, validateSignupPayload, validateTenantPayload, sanitizeString } from './lib/validation.js';
import { hashPBKDF2, verifyPBKDF2, verifyLegacy, fakeVerify, arrayBufferToHex, hexToArrayBuffer, generateTempPassword } from './lib/crypto.js';


export async function signup(request, env) {
  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const payload = parsed.data;
  const validation = validateSignupPayload(payload);
  if (!validation.ok) return json({ error: 'Invalid signup payload', details: validation.errors }, 400);

  const normalizedEmail = String(payload.email).trim().toLowerCase();
  const role = String(payload.role).trim().toLowerCase();

  let sanitizedName = null;
  if (payload.name) {
    const nameResult = sanitizeString(payload.name, 'name', 100);
    if (nameResult.ok) {
      sanitizedName = nameResult.value;
    }
  }

  let finalPassword = 'default@1234';
  let tempPassword = null;
  let mustChangePassword = 0;
  let tempPasswordExpires = null;

  if (role === 'tenant' || role === 'user') {
    const authUser = await getAuthUser(request, env);
    if (authUser.error) return json({ error: authUser.error }, authUser.status || 401);
    if (authUser.user.role !== 'admin') return json({ error: 'Forbidden' }, 403);

    tempPassword = generateTempPassword();
    finalPassword = tempPassword;
    mustChangePassword = 1;
    tempPasswordExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  } else if (role === 'admin') {
    if (!payload.code) return json({ error: 'Code is required for admin signup' }, 400);
    if (!payload.password) return json({ error: 'Password is required' }, 400);
    const passwordValidation = validatePassword(payload.password);
    if (!passwordValidation.ok) return json({ error: 'Password is too weak' }, 400);
    finalPassword = payload.password;
  } else {
    if (!payload.password) return json({ error: 'Password is required' }, 400);
    const passwordValidation = validatePassword(payload.password);
    if (!passwordValidation.ok) return json({ error: 'Password is too weak' }, 400);
    finalPassword = payload.password;
  }

  try {
    const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(normalizedEmail).first();
    if (existing) return json({ error: 'Email already exists' }, 400);

    const { hash: derivedBits, salt } = await hashPBKDF2(finalPassword);
    const hashHex = arrayBufferToHex(derivedBits);
    const saltHex = arrayBufferToHex(salt);

    const userInsert = await env.DB
      .prepare('INSERT INTO users (email, password_hash, password_salt, role, created_at, name, requires_change_password, temp_password_expiration) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(normalizedEmail, hashHex, saltHex, role, new Date().toISOString(), sanitizedName, mustChangePassword, tempPasswordExpires)
      .run();

    const userId = userInsert.meta?.last_row_id;
    if (!userId) return json({ error: 'Failed to create user' }, 500);

    if (role === 'tenant') {
      const tenantValidation = validateTenantPayload(payload);
      if (!tenantValidation.ok) return json({ error: 'Invalid tenant fields', details: tenantValidation.errors }, 400);

      await env.DB
        .prepare(`
          INSERT INTO tenants (user_id, balance, deposit, rent_amount, billing_cycle, leased_unit, onboard_date, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          userId,
          Number(payload.balance),
          Number(payload.deposit),
          Number(payload.rent_amount),
          String(payload.billing_cycle),
          String(payload.leased_unit),
          new Date(payload.onboard_date).toISOString(),
          new Date().toISOString()
        )
        .run();
    }

    if (role === 'admin') {
      const registrationCode = await env.DB.prepare('SELECT id FROM signup_keys WHERE code = ? AND used = 0').bind(payload.code).first();
      if (!registrationCode) return json({ error: 'Invalid code' }, 400);
      await env.DB.prepare('UPDATE signup_keys SET used = 1, user_id = ? WHERE id = ?').bind(userId, registrationCode.id).run();
    }

    return json({ success: true, message: 'User registered successfully', tempPassword });
  } catch (error) {
    console.error('Signup error:', error);
    return json({ error: 'Failed to create user', details: error.message }, 500);
  }
}

export async function login(request, env) {
  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const validation = validateLoginPayload(parsed.data);
  if (!validation.ok) return json({ error: 'Invalid login payload', details: validation.errors }, 400);

  try {
    const normalizedEmail = String(parsed.data.email).trim().toLowerCase();
    const user = await env.DB.prepare('SELECT id, password_hash, password_salt FROM users WHERE email = ?').bind(normalizedEmail).first();

    if (!user) {
      await fakeVerify();
      return json({ error: 'Invalid email or password' }, 401);
    }

    const valid = user.password_hash && user.password_salt
      ? await verifyPBKDF2(user.password_hash, user.password_salt, parsed.data.password)
      : await verifyLegacy(parsed.data.password, user.password_salt, user.password_hash);

    if (!valid) return json({ error: 'Invalid email or password' }, 401);

    const accessToken = await new SignJWT({ sub: user.id })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(getSecret(env));

    const refreshTokenRaw = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').bind(user.id, refreshTokenRaw, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()).run();

    return json({ success: true, accessToken, refreshToken: refreshTokenRaw });
  } catch (error) {
    console.error('Login error:', error);
    return json({ error: 'Authentication failed' }, 500);
  }
}

export async function updatePassword(request, env) {
  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const { token, oldPassword, newPassword } = parsed.data;
  if (!token || !oldPassword || !newPassword) return json({ error: 'Missing fields' }, 400);

  const passwordValidation = validatePassword(newPassword);
  if (!passwordValidation.ok) return json({ error: 'Password is too weak' }, 400);

  try {
    let payload;
    try {
      ({ payload } = await jwtVerify(token, getSecret(env)));
    } catch {
      return json({ error: 'Invalid or expired token' }, 401);
    }

    const user = await env.DB.prepare('SELECT id, password_hash, password_salt FROM users WHERE id = ?').bind(payload.sub).first();
    if (!user) return json({ error: 'User not found' }, 404);

    const valid = await verifyPBKDF2(user.password_hash, user.password_salt, oldPassword);
    if (!valid) return json({ error: 'Old password is incorrect' }, 401);

    const { hash: derivedBits, salt } = await hashPBKDF2(newPassword);
    await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').bind(arrayBufferToHex(derivedBits), arrayBufferToHex(salt), user.id).run();

    return json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Update password error:', error);
    return json({ error: 'Failed to update password' }, 500);
  }
}

export async function requestReset(request, env) {
  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const emailResult = validateEmail(parsed.data?.email);
  if (!emailResult.ok) return json({ error: 'Invalid email' }, 400);

  try {
    const normalizedEmail = String(parsed.data.email).trim().toLowerCase();
    const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(normalizedEmail).first();
    if (!user) return json({ success: true, message: 'If your email exists, a reset link has been sent' });

    const token = await new SignJWT({ sub: user.id }).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('1h').sign(getSecret(env));
    const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();
    await env.DB.prepare('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)').bind(user.id, token, expiresAt).run();

    return json({ success: true, message: 'If your email exists, a reset link has been sent' });
  } catch (error) {
    console.error('Request reset error:', error);
    return json({ success: true, message: 'If your email exists, a reset link has been sent' });
  }
}

export async function resetPassword(request, env) {
  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const { token, newPassword } = parsed.data;
  if (!token || !newPassword) return json({ error: 'Missing fields' }, 400);

  const passwordValidation = validatePassword(newPassword);
  if (!passwordValidation.ok) return json({ error: 'Password is too weak' }, 400);

  try {
    let payload;
    try {
      ({ payload } = await jwtVerify(token, getSecret(env)));
    } catch {
      return json({ error: 'Invalid or expired token' }, 400);
    }

    const reset = await env.DB.prepare('SELECT id, used, expires_at FROM password_resets WHERE token = ?').bind(token).first();
    if (!reset || reset.used || new Date(reset.expires_at) < new Date()) return json({ error: 'Invalid or expired token' }, 400);

    const { hash: derivedBits, salt } = await hashPBKDF2(newPassword);
    await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').bind(arrayBufferToHex(derivedBits), arrayBufferToHex(salt), payload.sub).run();
    await env.DB.prepare('UPDATE password_resets SET used = 1 WHERE id = ?').bind(reset.id).run();

    return json({ success: true, message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    return json({ error: 'Failed to reset password' }, 500);
  }
}

export async function verifyJwt(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return json({ error: 'Unauthorized' }, 401);

  const token = auth.slice(7);

  try {
    let payload;
    try {
      ({ payload } = await jwtVerify(token, getSecret(env)));
    } catch {
      return json({ error: 'Invalid or expired token' }, 401);
    }

    const user = await env.DB.prepare('SELECT id, email, role, name FROM users WHERE id = ?').bind(payload.sub).first();
    if (!user) return json({ error: 'User not found' }, 401);

    return json({ valid: true, user });
  } catch (error) {
    console.error('Verify JWT error:', error);
    return json({ error: 'Invalid or expired token' }, 401);
  }
}

export async function refreshToken(request, env) {
  const parsed = await parseJsonBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);

  const { refreshToken } = parsed.data;
  if (!refreshToken) return json({ error: 'No refresh token' }, 400);

  try {
    const row = await env.DB.prepare('SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?').bind(refreshToken).first();
    if (!row || new Date(row.expires_at) < new Date()) return json({ error: 'Invalid or expired refresh token' }, 401);

    const newAccessToken = await new SignJWT({ sub: row.user_id }).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('15m').sign(getSecret(env));
    return json({ success: true, accessToken: newAccessToken });
  } catch (error) {
    console.error('Refresh token error:', error);
    return json({ error: 'Failed to refresh token' }, 500);
  }
}

export async function getAuthUser(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth) return { error: 'Authorization header missing', status: 401 };
  if (!auth.startsWith('Bearer ')) return { error: 'Invalid Authorization format', status: 401 };

  const token = auth.slice(7);
  try {
    let payload;
    try {
      ({ payload } = await jwtVerify(token, getSecret(env)));
    } catch {
      return { error: 'Invalid or expired token', status: 401 };
    }

    const user = await env.DB.prepare('SELECT id, email, role, name FROM users WHERE id = ?').bind(payload.sub).first();
    if (!user) return { error: 'User not found', status: 404 };

    return { user };
  } catch (error) {
    console.error('Auth user error:', error);
    return { error: 'Authentication failed', status: 500 };
  }
}

function getSecret(env) {
  return new TextEncoder().encode(env.JWT_SCRT);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

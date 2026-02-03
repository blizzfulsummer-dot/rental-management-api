import { SignJWT, jwtVerify } from 'jose';
import { listTenants, getTenant, updateTenant, deleteTenant } from './tenant';

/* =========================
   WORKER FETCH
========================= */

const ALLOWED_ORIGINS = [
  'https://test-front-env.pages.dev',
  'https://my-other-site.pages.dev'
];

// Helper to attach CORS headers
function withCors(response, allowOrigin = "*") {
  response.headers.set('Access-Control-Allow-Origin', allowOrigin);
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return response;
}



export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    let allowOrigin = '*';
    if (origin && ALLOWED_ORIGINS.includes(origin)) {
      allowOrigin = origin;
    }

    // Handle preflight OPTIONS requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': allowOrigin,
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    
    try {
      const url = new URL(request.url);

      if (url.pathname === '/api/signup' && request.method === 'POST') {
        return withCors(await signup(request, env));
      }

      if (url.pathname === '/api/login' && request.method === 'POST') {
        return withCors(await login(request, env));
      }

      if (url.pathname === '/api/update_password' && request.method === 'POST') {
        return withCors(await updatePassword(request, env));
      }

      if (url.pathname === '/api/request_reset' && request.method === 'POST') {
        return withCors(await requestReset(request, env));
      }

      if (url.pathname === '/api/reset_password' && request.method === 'POST') {
        return withCors(await resetPassword(request, env));
      }

      if (url.pathname === '/api/refresh' && request.method === 'POST') {
        return withCors(await refreshToken(request, env));
      }

      if (url.pathname === '/api/me' && request.method === 'GET') {
        return withCors(await verifyJwt(request, env));
      }

      const { user, error, status } = await getAuthUser(request, env);
      if (error) return withCors(json({ error }, status));

      /* TENANTS */
      if (url.pathname === '/api/tenants' && request.method === 'POST') {
          return withCors(await createTenant(request, env, user));
      }

      if (url.pathname === '/api/tenants' && request.method === 'GET') {
          return withCors(await listTenants(request, env, user));
      }

      if (url.pathname.startsWith('/api/tenants/') ) {
          const id = url.pathname.split('/').pop();

        if (request.method === 'GET') {
            return withCors(await getTenant(request, env, user, id));
        }

        if (request.method === 'PUT') {
            return withCors(await updateTenant(request, env, user, id));
        }

        if (request.method === 'DELETE') {
            return withCors(await deleteTenant(request, env, user, id));
        }
      }



      return withCors(new Response('Rental Management Worker is running!', { status: 200 }));
    } catch (err) {
      console.error(err);
      return withCors(new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }));
    }
  }
};

/* =========================
   SIGNUP HANDLER
========================= */
async function signup(request, env) {
  const { email,
          password, 
          role , 
          name,
          balance,
          billing_cycle,
          rent_amount,
          deposit,
          leased_unit,
          onboard_date,
          code
          } = await request.json();
  if (!email || !role) return json({ error: 'Missing fields' }, 400);

  const allowedRole = ['admin', 'tenant', 'user'];

  const normalizeRole = role.trim().toLowerCase();

  if(!allowedRole.includes(normalizeRole)) return json({error:'Invalid Role'},400);

  let registrationCode;

  let finalPassword;
  let tempPassword = null;
  let mustChangePassword = 0;
  let tempPasswordExpires = null;

  if (normalizeRole === 'tenant' || normalizeRole === 'user') {
  
      const { user, error, status } = await getAuthUser(request, env);
      if (error) return withCors(json({ error }, status));

      if(user.role !== "admin"){
        return json({ error: 'Forbidden' }, 403);
      }

      tempPassword = generateTempPassword();
      finalPassword = tempPassword;
      mustChangePassword = 1;
      tempPasswordExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  } else {
      // admin or self-registered user
      if (!password) {
          return json({ error: 'Password required' }, 400);
      }
          finalPassword = password;
  }

  if(normalizeRole === "admin"){
    

    if(!code) return json({error: "Code is Required for the Account Type"}, 400);

    registrationCode = await env.DB.prepare('SELECT id FROM signup_keys WHERE code = ? AND used = 0').bind(code).first();

    if(!registrationCode || registrationCode.used===1) return json({ error: "Invalid Code for Account Type"}, 400);
  
  }

  const normalizedEmail = email.trim().toLowerCase();

  const existing = await env.DB
    .prepare('SELECT id FROM users WHERE email = ?')
    .bind(normalizedEmail)
    .first();

  if (existing) return json({ error: 'Email already exists' }, 400);


  const { hash: derivedBits, salt } = await hashPBKDF2(finalPassword);
  const hashHex = arrayBufferToHex(derivedBits);
  const saltHex = arrayBufferToHex(salt);

  const r = role?.trim().toLowerCase();

  const userInsert = await env.DB
    .prepare('INSERT INTO users (email, password_hash, password_salt, role, created_at, name, requires_change_password, temp_password_expiration) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(normalizedEmail, hashHex, saltHex, r, new Date().toISOString(), name, mustChangePassword, tempPasswordExpires)
    .run();

  // Get the inserted user's ID
  const userId = userInsert.lastInsertRowid;

  // Mark admin code as used and link to user
  if (normalizeRole === "admin") {
    await env.DB
      .prepare('UPDATE signup_keys SET used = 1, user_id = ? WHERE id = ?')
      .bind(userId, registrationCode.id)
      .run();
  }

  // If role is tenant, insert into tenants table
  if (r === 'tenant') {

    if (!balance || !rent_amount || !leased_unit || !onboard_date) {
      return json({ error: 'Missing tenant-specific fields' }, 400);
    }

    await env.DB
      .prepare(`
        INSERT INTO tenants 
          (user_id, balance, deposit, rent_amount, billing_cycle, leased_unit, onboard_date, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        userId,
        balance,
        deposit,
        rent_amount,
        billing_cycle,
        leased_unit,
        onboard_date,
        new Date().toISOString()
      )
      .run();
  }

  return json({ success: true, message: 'User registered successfully', tempPassword: tempPassword });
}

/*Create Temporary Password*/

function generateTempPassword(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$';
  let password = '';
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  for (let i = 0; i < length; i++) {
    password += chars[array[i] % chars.length];
  }
  return password;
}



/* =========================
   LOGIN HANDLER
========================= */
async function login(request, env) {
  const { email, password } = await request.json();
  if (!email || !password) return json({ error: 'Missing credentials' }, 400);

  const normalizedEmail = email.trim().toLowerCase();

  const user = await env.DB
    .prepare('SELECT id, password_hash, password_salt FROM users WHERE email = ?')
    .bind(normalizedEmail)
    .first();

  if (!user) {
    await fakeVerify();
    return json({ error: 'Invalid email or password' }, 401);
  }

  const valid = user.password_hash && user.password_salt
    ? await verifyPBKDF2(user.password_hash, user.password_salt, password)
    : await verifyLegacy(password, user.password_salt, user.password_hash);

  if (!valid) return json({ error: 'Invalid email or password' }, 401);

  // After verifying user password
const accessToken = await new SignJWT({ sub: user.id })
  .setProtectedHeader({ alg: 'HS256' })
  .setIssuedAt()
  .setExpirationTime('15m')
  .sign(getSecret(env));

// Generate refresh token
const refreshTokenRaw = crypto.randomUUID();

// Remove old refresh tokens 1 session allowed
/*

await env.DB
  .prepare('DELETE FROM refresh_tokens WHERE user_id = ?')
  .bind(user.id)
  .run();

*/

await env.DB
  .prepare('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)')
  .bind(user.id, refreshTokenRaw, new Date(Date.now() + 7*24*60*60*1000).toISOString())
  .run();

await env.DB
  .prepare(`
      DELETE FROM refresh_tokens
      WHERE user_id = ?
      AND id NOT IN (
      SELECT id FROM refresh_tokens
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 5
    )
  `)
  .bind(user.id, user.id)
  .run();


return json({ success: true, accessToken, refreshToken: refreshTokenRaw });
}

/* =========================
   UPDATE PASSWORD
   (authenticated user)
========================= */
async function updatePassword(request, env) {
  const { token, oldPassword, newPassword } = await request.json();
  if (!token || !oldPassword || !newPassword)
    return json({ error: 'Missing fields' }, 400);

  let payload;
  try {
    ({ payload } = await jwtVerify(token, getSecret(env)));
  } catch {
    return json({ error: 'Invalid or expired token' }, 401);
  }

  const user = await env.DB
    .prepare('SELECT id, password_hash, password_salt FROM users WHERE id = ?')
    .bind(payload.sub)
    .first();

  if (!user) return json({ error: 'User not found' }, 404);

  const valid = await verifyPBKDF2(user.password_hash, user.password_salt, oldPassword);
  if (!valid) return json({ error: 'Old password is incorrect' }, 401);

  const { hash: derivedBits, salt } = await hashPBKDF2(newPassword);
  const hashHex = arrayBufferToHex(derivedBits);
  const saltHex = arrayBufferToHex(salt);

  await env.DB
    .prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
    .bind(hashHex, saltHex, user.id)
    .run();

  return json({ success: true, message: 'Password updated successfully' });
}

/* =========================
   REQUEST RESET
   (forgot password)
========================= */
async function requestReset(request, env) {
  const { email } = await request.json();
  if (!email) return json({ error: 'Missing email' }, 400);

  const user = await env.DB
    .prepare('SELECT id FROM users WHERE email = ?')
    .bind(email.trim().toLowerCase())
    .first();

  if (!user) {
    return json({ success: true, message: 'If your email exists, a reset link has been sent' });
  }

  const token = await new SignJWT({ sub: user.id })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(getSecret(env));

  const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();

  await env.DB
    .prepare('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)')
    .bind(user.id, token, expiresAt)
    .run();

  console.log(`Password reset link: https://yourapp.com/reset-password?token=${token}`);

  return json({ success: true, message: 'If your email exists, a reset link has been sent' });
}

/* =========================
   RESET PASSWORD
   (forgot password)
========================= */
async function resetPassword(request, env) {
  const { token, newPassword } = await request.json();
  if (!token || !newPassword) return json({ error: 'Missing fields' }, 400);

  let payload;
  try {
    ({ payload } = await jwtVerify(token, getSecret(env)));
  } catch {
    return json({ error: 'Invalid or expired token' }, 400);
  }

  const reset = await env.DB
    .prepare('SELECT id, used, expires_at FROM password_resets WHERE token = ?')
    .bind(token)
    .first();

  if (!reset || reset.used || new Date(reset.expires_at) < new Date())
    return json({ error: 'Invalid or expired token' }, 400);

  const { hash: derivedBits, salt } = await hashPBKDF2(newPassword);
  const hashHex = arrayBufferToHex(derivedBits);
  const saltHex = arrayBufferToHex(salt);

  await env.DB
    .prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
    .bind(hashHex, saltHex, payload.sub)
    .run();

  await env.DB
    .prepare('UPDATE password_resets SET used = 1 WHERE id = ?')
    .bind(reset.id)
    .run();

  return json({ success: true, message: 'Password has been reset successfully' });
}

/* =========================
   JWT VERIFY / ME
========================= */
async function verifyJwt(request, env) {
  const auth = request.headers.get('Authorization');

  if (!auth || !auth.startsWith('Bearer ')) {
    return json({ error: 'Unauthorized' }, 401);
  }

  const token = auth.slice(7);

  let payload;
  try {
    ({ payload } = await jwtVerify(token, getSecret(env)));
  } catch (err) {
  
    if (err instanceof errors.JWTExpired) {
      // Token was valid but expired
      return json({ error: 'Expired Token' }, 401);
    }
    // Any other error means invalid token
    return json({ error: 'Invalid Token' }, 401);
  }

  // OPTIONAL but HIGHLY recommended
  const user = await env.DB
    .prepare('SELECT id, email, role, name FROM users WHERE id = ?')
    .bind(payload.sub)
    .first();

  if (!user) {
    return json({ error: 'User not found' }, 401);
  }

  return json({
    valid: true,
    user
  });
}


/* =========================
   REFRESH TOKEN
========================= */
async function refreshToken(request, env) {
  const { refreshToken } = await request.json();
  if (!refreshToken) return json({ error: 'No refresh token' }, 400);

  const row = await env.DB
    .prepare('SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?')
    .bind(refreshToken)
    .first();

  if (!row || new Date(row.expires_at) < new Date()) {
    return json({ error: 'Invalid or expired refresh token' }, 401);
  }

  const newAccessToken = await new SignJWT({ sub: row.user_id })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('15m') // short-lived
    .sign(getSecret(env));

  return json({ success: true, accessToken: newAccessToken });
}

/* =========================
   HELPERS
========================= */
function getSecret(env) {
  return new TextEncoder().encode(env.JWT_SCRT);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function fakeVerify() {
  await crypto.subtle.digest('SHA-256', new TextEncoder().encode('fake'));
}

async function verifyPBKDF2(storedHex, saltHex, password) {
  const salt = hexToArrayBuffer(saltHex);
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    256
  );

  return arrayBufferToHex(derivedBits) === storedHex;
}

async function verifyLegacy(password, salt, hash) {
  if (!salt) return false;
  const encoder = new TextEncoder();
  const data = encoder.encode(password + salt);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return arrayBufferToHex(digest) === hash;
}

async function hashPBKDF2(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' }, keyMaterial, 256
  );
  return { hash: derivedBits, salt };
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2,'0')).join('');
}

function hexToArrayBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i*2,2),16);
  return bytes;
}

async function getAuthUser(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth) {
    // No Authorization header at all
    return { error: 'Authorization header missing', status: 401 };
  }

  if (!auth.startsWith('Bearer ')) {
    // Header present but malformed
    return { error: 'Invalid Authorization format', status: 401 };
  }

  const token = auth.slice(7);
  let payload;

  try {
    ({ payload } = await jwtVerify(token, getSecret(env)));
  } catch {
    // Token invalid or expired
    return { error: 'Invalid or expired token', status: 401 };
  }

  const user = await env.DB
    .prepare('SELECT id, email, role, name FROM users WHERE id = ?')
    .bind(payload.sub)
    .first();

  if (!user) {
    return { error: 'User not found', status: 404 };
  }

  return { user }; // Success case
}



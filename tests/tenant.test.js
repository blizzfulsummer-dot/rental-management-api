import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT } from 'jose';
import { getAuthUser } from '../src/auth.js';
import { createDevice, createHouse, getTenant, listHouseDevices, listHouses, listTenants, updateTenant } from '../src/tenant.js';

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' }, keyMaterial, 256);
  return {
    hash: [...new Uint8Array(derivedBits)].map((byte) => byte.toString(16).padStart(2, '0')).join(''),
    salt: [...salt].map((byte) => byte.toString(16).padStart(2, '0')).join('')
  };
}

async function createDb() {
  const tenantRow = {
    id: 7,
    user_id: 42,
    balance: 100,
    deposit: 50,
    rent_amount: 1200,
    billing_cycle: 'monthly',
    leased_unit: 'A1',
    onboard_date: '2026-08-01'
  };

  const userRow = {
    id: 42,
    email: 'tenant@example.com',
    name: 'Tenant User',
    role: 'tenant'
  };

  const password = await hashPassword('OldPass123!');

  return {
    db: {
      prepare(sql) {
        return {
          bind(...args) {
            return {
              async first() {
                if (sql.includes('FROM user_house_access') && sql.includes('JOIN houses')) {
                  return { user_id: 42, house_id: 10 };
                }

                if (sql.includes('FROM houses WHERE id = ? AND owner_id = ?')) {
                  return { id: 10, owner_id: 1 };
                }

                if (sql.includes('FROM tenants') && sql.includes('JOIN users')) {
                  return { ...tenantRow, ...userRow };
                }

                if (sql.includes('SELECT id, password_hash, password_salt FROM users')) {
                  return { id: 42, password_hash: password.hash, password_salt: password.salt };
                }

                if (sql.includes('SELECT id, user_id FROM tenants')) {
                  return tenantRow;
                }

                if (sql.includes('UPDATE users SET password_hash')) {
                  return { success: true };
                }

                return tenantRow;
              },
              async all() {
                if (sql.includes('SELECT DISTINCT') && sql.includes('FROM tenants')) {
                  return { results: [{ ...tenantRow, email: userRow.email, name: userRow.name, role: userRow.role }] };
                }

                return { results: [] };
              },
              async run() {
                return { success: true };
              }
            };
          }
        };
      }
    }
  };
}

test('tenant can fetch their own basic profile info', async () => {
  const { db } = await createDb();
  const request = new Request('https://example.com/api/tenants/7');
  const response = await getTenant(request, { DB: db }, { id: 42, role: 'tenant' }, '7');
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.equal(payload.tenant.email, 'tenant@example.com');
  assert.equal(payload.tenant.name, 'Tenant User');
});

test('tenant can update their own password via tenant endpoint', async () => {
  const { db } = await createDb();
  const request = new Request('https://example.com/api/tenants/7', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword: 'OldPass123!', newPassword: 'NewPass123!' })
  });

  const response = await updateTenant(request, { DB: db }, { id: 42, role: 'tenant' }, '7');
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.equal(payload.success, true);
});

test('owner can list tenants assigned to their houses', async () => {
  const { db } = await createDb();
  const response = await listTenants({}, { DB: db }, { id: 1, role: 'owner' });
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.equal(payload.tenants.length, 1);
  assert.equal(payload.tenants[0].email, 'tenant@example.com');
});

test('admin can fetch an empty device list for an existing house', async () => {
  const { db } = await createDb();
  const response = await listHouseDevices({}, { DB: db }, { id: 1, role: 'admin' }, '10');
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(payload.devices, []);
});

test('auth user includes assigned houses from user_house_access', async () => {
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async first() {
              if (sql.includes('FROM users WHERE id = ?')) {
                return { id: 42, email: 'tenant@example.com', role: 'tenant', name: 'Tenant User' };
              }
              return null;
            },
            async all() {
              if (sql.includes('LEFT JOIN user_house_access')) {
                return {
                  results: [
                    { id: 7, name: 'Main House', location: 'A-12', owner_id: 1, created_at: '2026-01-01T00:00:00Z', house_uid: 'HSE-000007' }
                  ]
                };
              }
              return { results: [] };
            }
          };
        }
      };
    }
  };

  const token = await new SignJWT({ sub: 42 })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(new TextEncoder().encode('test-secret'));

  const request = new Request('https://example.com/api/me', {
    headers: { Authorization: `Bearer ${token}` }
  });

  const result = await getAuthUser(request, { DB: db, JWT_SCRT: 'test-secret' });

  assert.equal(result.user.role, 'tenant');
  assert.equal(result.user.assigned_house.name, 'Main House');
  assert.equal(result.user.assigned_houses[0].id, 7);
});

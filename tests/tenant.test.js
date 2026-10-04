import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT } from 'jose';
import { verifyJwt } from '../src/auth.js';
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
                if (sql.includes('LEFT JOIN user_device_access')) {
                  return { 1: 1 };
                }
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

test('house device list normalizes production name and type columns for the requested house', async () => {
  let queriedHouseId;
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          if (sql.includes('LEFT JOIN user_device_access')) {
            return { async first() { return { 1: 1 }; } };
          }

          if (sql.includes('FROM user_house_access')) {
            return { async first() { return { id: 1 }; } };
          }

          if (sql.includes('FROM devices d') || sql.includes('FROM devices WHERE house_id = ?')) {
            queriedHouseId = args[0];
            return {
              async all() {
                return {
                  results: [
                    { id: 12, house_id: 10, name: 'Main Gate', type: 'Timer', status: 'Online', last_seen: '2026-02-26' }
                  ]
                };
              }
            };
          }

          return { async first() { return null; }, async all() { return { results: [] }; } };
        }
      };
    }
  };

  const response = await listHouseDevices({}, { DB: db }, { id: 42, role: 'tenant' }, '10');
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.equal(queriedHouseId, 10);
  assert.equal(payload.devices[0].house_id, 10);
  assert.equal(payload.devices[0].device_name, 'Main Gate');
  assert.equal(payload.devices[0].device_type, 'Timer');
});

test('admin can create a device using production name and type columns', async () => {
  let insertSql;
  let insertValues;
  const db = {
    prepare(sql) {
      const prepared = {
        async all() {
          if (sql === 'PRAGMA table_info(devices)') {
            return {
              results: ['id', 'house_id', 'name', 'type', 'status', 'created_at', 'device_key_hash'].map(name => ({ name }))
            };
          }
          return { results: [] };
        },
        bind(...args) {
          if (sql === 'PRAGMA table_info(devices)') {
            return {
              async all() {
                return {
                  results: ['id', 'house_id', 'name', 'type', 'status', 'created_at', 'device_key_hash'].map(name => ({ name }))
                };
              }
            };
          }
          if (sql.startsWith('INSERT INTO devices')) {
            insertSql = sql;
            insertValues = args;
            return { async run() { return { meta: { last_row_id: 12 } }; } };
          }
          if (sql.includes('SELECT * FROM devices WHERE id = ?')) {
            return {
              async first() {
                return {
                  id: 12,
                  house_id: 10,
                  name: 'Entry Light',
                  type: 'Switch',
                  device_key_hash: insertValues[3]
                };
              }
            };
          }
          return { async first() { return null; }, async all() { return { results: [] }; } };
        }
      };
      return prepared;
    }
  };
  const request = new Request('https://example.com/api/houses/10/devices', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Entry Light', type: 'Switch', house_id: 10 })
  });

  const response = await createDevice(request, { DB: db }, { id: 1, role: 'admin' });
  const payload = await response.json();

  assert.equal(response.status, 201);
  assert.match(insertSql, /INSERT INTO devices \(house_id, name, type, device_key_hash, status, created_at\)/);
  assert.deepEqual(insertValues.slice(0, 3), [10, 'Entry Light', 'Switch']);
  assert.equal(payload.device.device_name, 'Entry Light');
  assert.equal(payload.device.pairing_configured, true);
  assert.equal(Object.hasOwn(payload.device, 'device_key_hash'), false);
});

test('tenant cannot create devices', async () => {
  const request = new Request('https://example.com/api/houses/10/devices', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Entry Light', type: 'Switch', house_id: 10 })
  });
  const createResponse = await createDevice(request, { DB: {} }, { id: 42, role: 'tenant' });

  assert.equal(createResponse.status, 403);
});

test('device access also makes the associated house visible to the user', async () => {
  let boundUserIds;
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          boundUserIds = args;
          return {
            async all() {
              assert.match(sql, /JOIN user_device_access uda ON uda\.device_id = d\.id/);
              return {
                results: [
                  { id: 3, name: 'Device House', address: 'Street 3', owner_id: 1, created_at: '2026-01-01' }
                ]
              };
            }
          };
        }
      };
    }
  };

  const response = await listHouses({}, { DB: db }, { id: 42, role: 'tenant' });
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(boundUserIds, [42, 42, 42]);
  assert.equal(payload.houses[0].id, 3);
  assert.equal(payload.houses[0].location, 'Street 3');
});

test('owner can see houses explicitly granted through user_house_access', async () => {
  let boundUserIds;
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          boundUserIds = args;
          return {
            async all() {
              assert.match(sql, /uha\.user_id = \?/);
              return {
                results: [
                  { id: 8, name: 'Shared House', address: 'Street 8', owner_id: 7, created_at: '2026-01-01' }
                ]
              };
            }
          };
        }
      };
    }
  };

  const response = await listHouses({}, { DB: db }, { id: 42, role: 'owner' });
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(boundUserIds, [42, 42, 42]);
  assert.equal(payload.houses[0].id, 8);
  assert.equal(payload.houses[0].location, 'Street 8');
});

test('owner can list only explicitly assigned devices in a shared house', async () => {
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async first() {
              if (sql.includes('FROM houses WHERE id = ? AND owner_id = ?')) return null;
              assert.match(sql, /user_house_access/);
              return { 1: 1 };
            },
            async all() {
              assert.match(sql, /JOIN user_device_access uda/);
              assert.deepEqual(args, [8, 42]);
              return { results: [{ id: 12, house_id: 8, name: 'Entry Device', type: 'lock' }] };
            }
          };
        }
      };
    }
  };

  const response = await listHouseDevices({}, { DB: db }, { id: 42, role: 'owner' }, '8');
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.equal(payload.devices[0].id, 12);
});

test('profile endpoint includes assigned houses using production address column', async () => {
  const db = {
    prepare(sql) {
      return {
        bind() {
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
                    { id: 7, name: 'Main House', address: 'A-12', owner_id: 1, created_at: '2026-01-01T00:00:00Z', house_uid: 'HSE-000007' }
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

  const response = await verifyJwt(request, { DB: db, JWT_SCRT: 'test-secret' });
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.equal(result.user.role, 'tenant');
  assert.equal(result.user.assigned_house.name, 'Main House');
  assert.equal(result.user.assigned_house.location, 'A-12');
  assert.equal(result.user.assigned_houses[0].id, 7);
});

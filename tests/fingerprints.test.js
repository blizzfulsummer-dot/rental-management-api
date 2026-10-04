import test from 'node:test';
import assert from 'node:assert/strict';
import { removeFingerprintEnrollment, startFingerprintEnrollment } from '../src/fingerprints.js';

function createDatabase({ hasAccess = true, fingerprintId = 1 } = {}) {
  const statements = [];
  return {
    statements,
    prepare(sql) {
      return {
        bind(...values) {
          statements.push({ sql, values });
          return {
            first: async () => {
              if (sql.includes('FROM devices d')) return { id: 8, house_id: 2, owner_id: 4 };
              if (sql.includes('FROM user_device_access')) return hasAccess ? { allowed: 1 } : null;
              if (sql.includes('FROM device_fingerprint_enrollments WHERE device_id = ? AND user_id = ?')) return null;
              if (sql.includes('WITH RECURSIVE ids')) return fingerprintId ? { fingerprint_id: fingerprintId } : null;
              return null;
            },
            run: async () => ({ success: true })
          };
        }
      };
    }
  };
}

test('fingerprint enrollment reserves an available template slot for the signed-in user', async () => {
  const DB = createDatabase({ fingerprintId: 3 });
  const response = await startFingerprintEnrollment({ DB }, { id: 19, role: 'tenant' }, '8');
  const body = await response.json();

  assert.equal(response.status, 201);
  assert.equal(body.fingerprintId, 3);
  assert.equal(body.houseId, 2);
  const insert = DB.statements.find(statement => statement.sql.includes('INSERT INTO device_fingerprint_enrollments'));
  assert.deepEqual(insert.values.slice(0, 3), [8, 19, 3]);
  assert.equal(typeof insert.values[3], 'string');
  assert.equal(insert.values[4], insert.values[3]);
});

test('fingerprint enrollment is rejected when the user has no access to the device', async () => {
  const DB = createDatabase({ hasAccess: false });
  const response = await startFingerprintEnrollment({ DB }, { id: 19, role: 'tenant' }, '8');

  assert.equal(response.status, 403);
  assert.equal(DB.statements.some(statement => statement.sql.includes('WITH RECURSIVE ids')), false);
});

test('tenants cannot disable or delete fingerprints', async () => {
  const response = await removeFingerprintEnrollment(
    new Request('https://api.example/api/devices/8/fingerprints/3', {
      method: 'DELETE',
      body: JSON.stringify({ action: 'delete' })
    }),
    { DB: createDatabase() },
    { id: 19, role: 'tenant' },
    '8',
    '3'
  );

  assert.equal(response.status, 403);
});

test('device owner can disable a fingerprint after confirming the device operation', async () => {
  const statements = [];
  const DB = {
    prepare(sql) {
      return {
        bind(...values) {
          statements.push({ sql, values });
          return {
            first: async () => sql.includes('FROM devices d')
              ? { id: 8, house_id: 2, owner_id: 4 }
              : { fingerprint_id: 3 },
            run: async () => ({ success: true })
          };
        }
      };
    }
  };
  const response = await removeFingerprintEnrollment(
    new Request('https://api.example/api/devices/8/fingerprints/3', {
      method: 'DELETE',
      body: JSON.stringify({ action: 'disable' })
    }),
    { DB },
    { id: 4, role: 'owner' },
    '8',
    '3'
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.action, 'disable');
  assert.match(statements.at(-1).sql, /SET status = 'disabled'/);
});

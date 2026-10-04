import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createDevice, rotateDevicePairingKey } from '../src/tenant.js';
import { issueDeviceWebSocketTicket } from '../src/lib/websocketTicket.js';

globalThis.crypto ??= webcrypto;

function createPairingDb() {
  const columns = ['id', 'house_id', 'name', 'type', 'status', 'created_at', 'device_key_hash'];
  const state = { device: null, ticketInserted: false };
  const DB = {
    prepare(sql) {
      return {
        async all() {
          if (sql.includes('PRAGMA table_info(devices)')) {
            return { results: columns.map(name => ({ name })) };
          }
          return { results: [] };
        },
        bind(...values) {
          if (sql.includes('PRAGMA table_info(devices)')) {
            return { async all() { return { results: columns.map(name => ({ name })) }; } };
          }
          if (sql.startsWith('INSERT INTO devices')) {
            return {
              async run() {
                state.device = {
                  id: 7,
                  house_id: values[0],
                  name: values[1],
                  type: values[2],
                  device_key_hash: values[3],
                  status: values[4],
                  created_at: values[5]
                };
                return { meta: { last_row_id: 7 } };
              }
            };
          }
          if (sql === 'SELECT * FROM devices WHERE id = ?') {
            return { async first() { return state.device; } };
          }
          if (sql === 'UPDATE devices SET device_key_hash = ? WHERE id = ?') {
            return {
              async run() {
                state.device.device_key_hash = values[0];
                return { success: true };
              }
            };
          }
          if (sql.includes('FROM devices d') && sql.includes('device_key_hash = ?')) {
            return {
              async first() {
                return values[1] === state.device?.device_key_hash
                  ? { id: 7, house_id: 10, owner_id: 3 }
                  : null;
              }
            };
          }
          if (sql.includes('INSERT INTO websocket_tickets')) {
            return {
              async run() {
                state.ticketInserted = true;
                return { success: true };
              }
            };
          }
          return { async first() { return null; }, async run() { return { success: true }; } };
        }
      };
    }
  };
  return { DB, state };
}

test('device creation returns a one-time key but persists and exposes only its hash', async () => {
  const { DB, state } = createPairingDb();
  const request = new Request('https://example.com/api/houses/10/devices', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ house_id: 10, name: 'ESP32 Switch', type: 'switch' })
  });

  const response = await createDevice(request, { DB }, { id: 3, role: 'admin' });
  const body = await response.json();
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body.pairing_key));
  const expectedHash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');

  assert.equal(response.status, 201);
  assert.match(body.pairing_key, /^[a-f0-9]{64}$/);
  assert.equal(state.device.device_key_hash, expectedHash);
  assert.equal(body.device.pairing_configured, true);
  assert.equal(Object.hasOwn(body.device, 'device_key_hash'), false);
});

test('device pairing key exchanges for a bound ticket and rejects an incorrect key', async () => {
  const { DB, state } = createPairingDb();
  const createResponse = await createDevice(new Request('https://example.com/api/devices', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ house_id: 10, name: 'ESP32 Switch', type: 'switch' })
  }), { DB }, { id: 3, role: 'admin' });
  const { pairing_key: pairingKey } = await createResponse.json();

  const requestTicket = key => new Request('https://example.com/ws/device-ticket', {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 7 })
  });
  const insecureResponse = await issueDeviceWebSocketTicket(new Request('http://example.com/ws/device-ticket', {
    method: 'POST',
    headers: { Authorization: `Bearer ${pairingKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 7 })
  }), { DB });
  assert.equal(insecureResponse.status, 426);
  assert.equal(state.ticketInserted, false);

  const validResponse = await issueDeviceWebSocketTicket(requestTicket(pairingKey), { DB });
  const validBody = await validResponse.json();

  assert.equal(validResponse.status, 200);
  assert.equal(validBody.deviceId, 7);
  assert.equal(validBody.houseId, 10);
  assert.equal(state.ticketInserted, true);

  state.ticketInserted = false;
  const invalidResponse = await issueDeviceWebSocketTicket(requestTicket('0'.repeat(64)), { DB });
  assert.equal(invalidResponse.status, 401);
  assert.equal(state.ticketInserted, false);
});

test('admin key rotation revokes the previous pairing key', async () => {
  const { DB, state } = createPairingDb();
  const createResponse = await createDevice(new Request('https://example.com/api/devices', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ house_id: 10, name: 'ESP32 Switch', type: 'switch' })
  }), { DB }, { id: 3, role: 'admin' });
  const { pairing_key: previousKey } = await createResponse.json();

  const ownerResponse = await rotateDevicePairingKey(new Request('https://example.com/api/devices/7/pairing-key', {
    method: 'POST'
  }), { DB }, { id: 3, role: 'owner' }, '7');
  assert.equal(ownerResponse.status, 403);

  const rotateResponse = await rotateDevicePairingKey(new Request('https://example.com/api/devices/7/pairing-key', {
    method: 'POST'
  }), { DB }, { id: 3, role: 'admin' }, '7');
  const { pairing_key: nextKey } = await rotateResponse.json();
  assert.equal(rotateResponse.status, 200);
  assert.notEqual(nextKey, previousKey);

  const oldKeyResponse = await issueDeviceWebSocketTicket(new Request('https://example.com/ws/device-ticket', {
    method: 'POST',
    headers: { Authorization: `Bearer ${previousKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 7 })
  }), { DB });
  assert.equal(oldKeyResponse.status, 401);
  assert.equal(state.ticketInserted, false);
});

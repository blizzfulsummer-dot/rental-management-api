import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT } from 'jose';
import { issueWebSocketTicket } from '../src/lib/websocketTicket.js';

async function makeRequest(secret, body) {
  const token = await new SignJWT({ sub: 42 })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(new TextEncoder().encode(secret));

  return new Request('https://example.com/ws/ticket', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
}

function makeDb({ hasDeviceAccess, role = 'tenant', ownsHouse = false }) {
  let ticketInserted = false;
  const DB = {
    prepare(sql) {
      return {
        bind(...args) {
          if (sql.includes('SELECT id, role FROM users')) {
            return { async first() { return { id: 42, role }; } };
          }
          if (sql.includes('SELECT id, house_id FROM devices')) {
            return { async first() { return { id: args[0], house_id: args[1] }; } };
          }
          if (sql.includes('FROM user_device_access')) {
            return { async first() { return hasDeviceAccess ? { 1: 1 } : null; } };
          }
          if (sql.includes('SELECT id FROM houses WHERE id = ? AND owner_id = ?')) {
            return { async first() { return ownsHouse ? { id: args[0] } : null; } };
          }
          if (sql.includes('INSERT INTO websocket_tickets')) {
            return {
              async run() {
                ticketInserted = true;
                return { success: true };
              }
            };
          }
          return { async first() { return null; }, async run() { return { success: true }; } };
        }
      };
    }
  };
  return { DB, ticketWasInserted: () => ticketInserted };
}

test('tenant receives a control ticket only for a device in user_device_access', async () => {
  const secret = 'device-ticket-test-secret';
  const { DB, ticketWasInserted } = makeDb({ hasDeviceAccess: false });
  const request = await makeRequest(secret, { houseId: 10, deviceId: 7, clientType: 'web' });

  const response = await issueWebSocketTicket(request, { DB, JWT_SCRT: secret });
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, 'Access denied to this device');
  assert.equal(ticketWasInserted(), false);
});

test('tenant receives a control ticket for an explicitly granted device', async () => {
  const secret = 'device-ticket-test-secret';
  const { DB, ticketWasInserted } = makeDb({ hasDeviceAccess: true });
  const request = await makeRequest(secret, { houseId: 10, deviceId: 7, clientType: 'web' });

  const response = await issueWebSocketTicket(request, { DB, JWT_SCRT: secret });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.houseId, 10);
  assert.equal(ticketWasInserted(), true);
});

test('owner with user_device_access can control an assigned device in a shared house', async () => {
  const secret = 'device-ticket-test-secret';
  const { DB, ticketWasInserted } = makeDb({ hasDeviceAccess: true, role: 'owner', ownsHouse: false });
  const request = await makeRequest(secret, { houseId: 10, deviceId: 7, clientType: 'web' });

  const response = await issueWebSocketTicket(request, { DB, JWT_SCRT: secret });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.houseId, 10);
  assert.equal(ticketWasInserted(), true);
});

test('owner without ownership or device access cannot control a device in a shared house', async () => {
  const secret = 'device-ticket-test-secret';
  const { DB, ticketWasInserted } = makeDb({ hasDeviceAccess: false, role: 'owner', ownsHouse: false });
  const request = await makeRequest(secret, { houseId: 10, deviceId: 7, clientType: 'web' });

  const response = await issueWebSocketTicket(request, { DB, JWT_SCRT: secret });
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, 'Access denied to this device');
  assert.equal(ticketWasInserted(), false);
});

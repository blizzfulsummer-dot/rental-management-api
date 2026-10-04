import test from 'node:test';
import assert from 'node:assert/strict';
import { HouseRoom } from '../src/houseRoom.js';

function createSession(role, deviceId) {
  const messages = [];
  return {
    messages,
    ws: { send(message) { messages.push(JSON.parse(message)); } },
    userId: 42,
    role,
    deviceId,
    clientType: 'web'
  };
}

test('house room refuses commands for devices other than the ticketed device', () => {
  const room = new HouseRoom({ id: 'house-10' }, {});
  const session = createSession('tenant', 7);
  room.sessions.set('web-session', session);

  room.handleDeviceCommand('web-session', session, {
    targetDeviceId: 8,
    command: 'on'
  });

  assert.equal(session.messages.length, 1);
  assert.equal(session.messages[0].type, 'error');
  assert.match(session.messages[0].error, /not authorized/);
});

test('house room routes a command to the ticketed device session', () => {
  const room = new HouseRoom({ id: 'house-10' }, {});
  const sender = createSession('tenant', 7);
  const deviceMessages = [];
  room.sessions.set('web-session', sender);
  room.sessions.set('device-session', {
    clientType: 'device',
    deviceId: 7,
    ws: { send(message) { deviceMessages.push(JSON.parse(message)); } }
  });

  room.handleDeviceCommand('web-session', sender, {
    targetDeviceId: 7,
    command: 'io.set',
    id: 'relay2',
    state: true
  });

  assert.equal(deviceMessages[0].deviceId, 7);
  assert.equal(deviceMessages[0].command, 'io.set');
  assert.equal(deviceMessages[0].id, 'relay2');
  assert.equal(deviceMessages[0].state, true);
  assert.equal(sender.messages[0].type, 'command_routed');
});

test('house room only broadcasts a device response matching the paired device', () => {
  const room = new HouseRoom({ id: 'house-10' }, {});
  const webSession = createSession('tenant', 7);
  const deviceSessionMessages = [];
  room.sessions.set('web-session', webSession);
  const deviceSession = {
    clientType: 'device',
    deviceId: 7,
    ws: { send(message) { deviceSessionMessages.push(JSON.parse(message)); } }
  };

  room.handleDeviceResponse('device-session', deviceSession, {
    deviceId: 8,
    success: true
  });
  assert.equal(deviceSessionMessages[0].type, 'error');
  assert.equal(webSession.messages.length, 0);

  room.handleDeviceResponse('device-session', deviceSession, {
    deviceId: 7,
    success: true
  });
  assert.equal(webSession.messages[0].type, 'device_response');
  assert.equal(webSession.messages[0].deviceId, 7);
});

test('authorized fingerprint recognition unlocks the paired door and stays device-scoped', async () => {
  const room = new HouseRoom({ id: 'house-10' }, {
    DB: {
      prepare(sql) {
        assert.match(sql, /device_fingerprint_enrollments/);
        return {
          bind(deviceId, fingerprintId) {
            assert.equal(deviceId, 7);
            assert.equal(fingerprintId, 12);
            return { first: async () => ({ user_id: 42 }) };
          }
        };
      }
    }
  });
  const webSession = createSession('tenant', 7);
  const otherDeviceWeb = createSession('tenant', 8);
  const otherUserWeb = createSession('tenant', 7);
  otherUserWeb.userId = 99;
  const deviceMessages = [];
  const deviceSession = {
    clientType: 'device',
    deviceId: 7,
    ws: { send(message) { deviceMessages.push(JSON.parse(message)); } }
  };
  room.sessions.set('web-session', webSession);
  room.sessions.set('other-device-web', otherDeviceWeb);
  room.sessions.set('other-user-web', otherUserWeb);
  room.sessions.set('device-session', deviceSession);

  await room.handleFingerprintEvent('device-session', deviceSession, {
    event: 'recognized',
    success: true,
    id: 12
  });

  assert.equal(deviceMessages[0].command, 'door.unlock');
  assert.equal(webSession.messages[0].accessGranted, true);
  assert.equal(otherDeviceWeb.messages.length, 0);
  assert.equal(otherUserWeb.messages.length, 0);
});

test('unregistered fingerprint recognition never unlocks the door', async () => {
  const room = new HouseRoom({ id: 'house-10' }, {
    DB: { prepare() { return { bind() { return { first: async () => null }; } }; } }
  });
  const webSession = createSession('owner', 7);
  const deviceMessages = [];
  const deviceSession = {
    clientType: 'device',
    deviceId: 7,
    ws: { send(message) { deviceMessages.push(JSON.parse(message)); } }
  };
  room.sessions.set('web-session', webSession);
  room.sessions.set('device-session', deviceSession);

  await room.handleFingerprintEvent('device-session', deviceSession, {
    event: 'recognized',
    success: true,
    id: 12
  });

  assert.equal(deviceMessages.length, 0);
  assert.equal(webSession.messages[0].accessGranted, false);
});

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
    command: 'on'
  });

  assert.equal(deviceMessages[0].deviceId, 7);
  assert.equal(deviceMessages[0].command, 'on');
  assert.equal(sender.messages[0].type, 'command_routed');
});

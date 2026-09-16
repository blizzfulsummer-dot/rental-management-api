#!/usr/bin/env node

/**
 * Simple IoT Device Simulator for Testing WebSocket Smart Home System
 * 
 * This script simulates an IoT device (like ESP32) connecting to the WebSocket room
 * and sending periodic status updates.
 * 
 * Usage:
 *   node device-simulator.js
 * 
 * Configuration:
 *   - API_URL: Cloudflare Worker API endpoint
 *   - DEVICE_ID: Which device to simulate (must exist in database)
 *   - DEVICE_TYPE: Type of device (light, thermostat, etc.)
 *   - SIMULATE_COMMANDS: Whether to respond to commands with status updates
 */

import WebSocket from 'ws';

// ============= CONFIGURATION =============
const API_URL = process.env.API_URL || 'http://localhost:8787';
const WS_URL = process.env.WS_URL || 'ws://localhost:8787';
const DEVICE_ID = parseInt(process.env.DEVICE_ID || '1');
const DEVICE_TYPE = process.env.DEVICE_TYPE || 'light';
const DEVICE_NAME = process.env.DEVICE_NAME || 'Simulated Device';
const HOUSE_ID = parseInt(process.env.HOUSE_ID || '1');
const API_KEY = process.env.DEVICE_API_KEY || 'device-api-key-demo'; // Replace with real auth
const SIMULATE_COMMANDS = process.env.SIMULATE_COMMANDS !== 'false';

// ============= STATE =============
let ws = null;
let sessionId = null;
let currentStatus = 'online';
let currentPower = 'off';
let isConnected = false;

// ============= LOGGING =============
function log(message, type = 'INFO') {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${type}] ${message}`);
}

function logError(message) {
  log(message, 'ERROR');
}

function logSuccess(message) {
  log(message, 'SUCCESS');
}

function logWebSocket(message) {
  log(message, 'WS');
}

// ============= DEVICE AUTHENTICATION =============
/**
 * Get device JWT token for WebSocket access
 * In production, this would use a real device authentication system
 */
async function getDeviceToken() {
  try {
    log(`Requesting device token for device ${DEVICE_ID}...`);

    // In production, this would:
    // 1. Use pre-issued device JWT
    // 2. Or exchange API key for JWT
    // 3. Or use device certificate

    // For testing, we simulate admin JWT and get ticket as device
    const loginResponse = await fetch(`${API_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'admin@example.com',
        password: 'AdminPass123!'
      })
    });

    if (!loginResponse.ok) {
      throw new Error(`Login failed: ${loginResponse.statusText}`);
    }

    const { access_token } = await loginResponse.json();
    logSuccess(`Got admin JWT token (simulating device auth)`);
    return access_token;
  } catch (error) {
    logError(`Failed to get device token: ${error.message}`);
    throw error;
  }
}

/**
 * Get WebSocket ticket for device
 */
async function getWebSocketTicket(jwt) {
  try {
    log(`Requesting WebSocket ticket...`);

    const response = await fetch(`${API_URL}/ws/ticket`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${jwt}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        houseId: HOUSE_ID,
        clientType: 'device',
        deviceId: DEVICE_ID
      })
    });

    if (!response.ok) {
      throw new Error(`Ticket request failed: ${response.statusText}`);
    }

    const { ticket, sessionId: sid } = await response.json();
    logSuccess(`Got WebSocket ticket (expires in 60s)`);
    return { ticket, sessionId: sid };
  } catch (error) {
    logError(`Failed to get WebSocket ticket: ${error.message}`);
    throw error;
  }
}

// ============= WEBSOCKET MANAGEMENT =============
/**
 * Connect to WebSocket room as IoT device
 */
async function connectToWebSocket() {
  try {
    // Get JWT
    const jwt = await getDeviceToken();

    // Get ticket
    const { ticket, sessionId: sid } = await getWebSocketTicket(jwt);
    sessionId = sid;

    // Connect to WebSocket
    const wsUrl = `${WS_URL}/ws/house/${HOUSE_ID}?ticket=${ticket}`;
    logWebSocket(`Connecting to ${wsUrl}...`);

    ws = new WebSocket(wsUrl);

    ws.on('open', () => {
      isConnected = true;
      logWebSocket(`✓ WebSocket connected (sessionId: ${sessionId})`);
      sendInitialStatus();
    });

    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data);
        handleWebSocketMessage(message);
      } catch (e) {
        logError(`Failed to parse message: ${e.message}`);
      }
    });

    ws.on('error', (error) => {
      logError(`WebSocket error: ${error.message}`);
      isConnected = false;
    });

    ws.on('close', () => {
      logWebSocket(`WebSocket closed`);
      isConnected = false;
      
      // Reconnect after 5 seconds
      log(`Will reconnect in 5 seconds...`);
      setTimeout(() => connectToWebSocket(), 5000);
    });

  } catch (error) {
    logError(`Connection failed: ${error.message}`);
    log(`Retrying in 10 seconds...`);
    setTimeout(() => connectToWebSocket(), 10000);
  }
}

/**
 * Send initial device status when connected
 */
function sendInitialStatus() {
  if (!isConnected) return;

  logWebSocket(`Sending initial device status...`);
  ws.send(JSON.stringify({
    type: 'device_update',
    deviceId: DEVICE_ID,
    deviceName: DEVICE_NAME,
    deviceType: DEVICE_TYPE,
    status: currentPower,
    power: currentPower,
    temperature: Math.random() * 10 + 20, // 20-30°C
    humidity: Math.random() * 30 + 40,    // 40-70%
    timestamp: new Date().toISOString()
  }));
}

/**
 * Handle incoming WebSocket messages
 */
function handleWebSocketMessage(message) {
  logWebSocket(`Received: ${message.type}`);

  switch (message.type) {
    case 'connected':
      logSuccess(`✓ Joined house room as device`);
      break;

    case 'user_joined':
      log(`👤 ${message.clientType || 'Client'} joined (ID: ${message.userId})`);
      break;

    case 'user_left':
      log(`👤 ${message.clientType || 'Client'} left (ID: ${message.userId})`);
      break;

    case 'device_command':
      if (message.deviceId === DEVICE_ID) {
        handleDeviceCommand(message);
      }
      break;

    case 'ping':
      if (isConnected) {
        ws.send(JSON.stringify({
          type: 'pong',
          timestamp: new Date().toISOString()
        }));
      }
      break;

    case 'error':
      logError(`Server error: ${message.message}`);
      break;

    default:
      log(`Unhandled message type: ${message.type}`);
  }
}

/**
 * Handle incoming device commands (e.g., turn on/off)
 */
function handleDeviceCommand(message) {
  log(`📥 Received command: ${message.command}`);

  if (!SIMULATE_COMMANDS) {
    log(`Command simulation disabled`);
    return;
  }

  // Simulate command execution
  const command = message.command.toLowerCase();
  
  if (command === 'on' || command === 'turn_on') {
    currentPower = 'on';
    log(`✓ Device turned ON`);
  } else if (command === 'off' || command === 'turn_off') {
    currentPower = 'off';
    log(`✓ Device turned OFF`);
  } else if (command === 'toggle') {
    currentPower = currentPower === 'on' ? 'off' : 'on';
    log(`✓ Device toggled to ${currentPower}`);
  } else {
    log(`Received unknown command: ${command}`);
    return;
  }

  // Send status update back
  setTimeout(() => {
    sendStatusUpdate(`Device ${currentPower} after command`);
  }, 500);
}

/**
 * Send periodic status updates (simulates sensor readings)
 */
function sendStatusUpdate(reason) {
  if (!isConnected) return;

  const temperature = Math.random() * 10 + 20;
  const humidity = Math.random() * 30 + 40;

  logWebSocket(`Sending status update: ${reason}`);
  ws.send(JSON.stringify({
    type: 'device_update',
    deviceId: DEVICE_ID,
    deviceName: DEVICE_NAME,
    deviceType: DEVICE_TYPE,
    status: currentPower,
    power: currentPower,
    temperature: temperature.toFixed(1),
    humidity: humidity.toFixed(1),
    batteryLevel: Math.random() * 20 + 80,
    signal: Math.random() * 30 + 60,
    reason: reason,
    timestamp: new Date().toISOString()
  }));
}

/**
 * Start periodic status broadcasts
 */
function startStatusBroadcast() {
  // Send status every 30 seconds
  setInterval(() => {
    if (isConnected) {
      sendStatusUpdate('Periodic update');
    }
  }, 30000);

  // Also send a quick update after 5 seconds of connection
  setTimeout(() => {
    if (isConnected) {
      sendStatusUpdate('Post-connection status');
    }
  }, 5000);
}

// ============= STARTUP =============
console.log(`
╔════════════════════════════════════════╗
║   IoT Device Simulator                 ║
║   Smart Home WebSocket Testing         ║
╚════════════════════════════════════════╝

Configuration:
  API URL:        ${API_URL}
  WebSocket URL:  ${WS_URL}
  Device ID:      ${DEVICE_ID}
  Device Name:    ${DEVICE_NAME}
  Device Type:    ${DEVICE_TYPE}
  House ID:       ${HOUSE_ID}
  Simulate Cmds:  ${SIMULATE_COMMANDS}

Connecting...
`);

async function main() {
  try {
    await connectToWebSocket();
    startStatusBroadcast();
  } catch (error) {
    logError(`Fatal error: ${error.message}`);
    process.exit(1);
  }
}

process.on('SIGINT', () => {
  log('Shutting down...');
  if (ws) {
    ws.close();
  }
  process.exit(0);
});

main();

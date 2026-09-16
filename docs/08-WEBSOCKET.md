# WebSocket Smart Home Room System

Real-time WebSocket communication for smart-home rental management. Enables authenticated web clients and IoT devices to communicate within a house room via Cloudflare Durable Objects.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Frontend Web Client                        │
│              (Browser, Smart-home app, etc.)                │
└────────────────┬────────────────────────────────────────────┘
                 │ 1. JWT Login
                 ▼
         ┌──────────────────┐
         │  Auth Endpoint   │
         │ POST /api/login  │
         └────────┬─────────┘
                  │ 2. JWT Access Token
                  ▼
         ┌──────────────────────┐
         │   Issue Ticket       │
         │ POST /ws/ticket      │
         │ + JWT + houseId      │
         └────────┬─────────────┘
                  │ 3. Short-lived Ticket (60 seconds)
                  ▼
     ┌───────────────────────────────────────┐
     │   WebSocket Connection                │
     │ wss://domain/ws/house/1?ticket=xyz    │
     └────────┬────────────────────────────┬─┘
              │                            │
              ▼                            ▼
   ┌─────────────────────┐      ┌─────────────────────┐
   │   Cloudflare        │      │   HouseRoom         │
   │   Worker            │      │   Durable Object    │
   │                     │      │                     │
   │ Validate ticket     │      │ • Accept connection │
   │ Route to Durable    │      │ • Route messages    │
   │ Object              │      │ • Manage sessions   │
   └─────────────────────┘      └─────────────────────┘
                                         ▲
                                         │
                                         ▼
                         ┌──────────────────────────┐
                         │   IoT Device (ESP32)     │
                         │ WebSocket client         │
                         │ Real-time commands       │
                         └──────────────────────────┘
```

## Security Model

### 1. JWT-based Authentication
- User logs in via existing auth endpoint
- Receives long-lived JWT (15 minutes)
- JWT is NOT used directly in WebSocket URL (unsafe in query params)

### 2. Short-lived WebSocket Tickets
- Frontend exchanges JWT for a ticket via `/ws/ticket` endpoint
- Ticket is valid for 60 seconds only
- Ticket is single-use (marked consumed after first use)
- Ticket is bound to:
  - Specific user
  - Specific house
  - Specific client type (web/device)
  - Optional: specific device ID

### 3. Validation Chain
```
Request → Ticket Validation → JWT Verification → 
Permission Check → Session Metadata → Durable Object Connection
```

## API Endpoints

### POST /ws/ticket

Issue a short-lived WebSocket ticket.

**Authentication:** Required (Authorization: Bearer JWT)

**Request:**
```bash
curl -X POST https://api.your-domain.com/ws/ticket \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "houseId": 1,
    "clientType": "web",
    "deviceId": null
  }'
```

**Request Body:**
```json
{
  "houseId": 1,                    // Required: numeric house ID
  "clientType": "web",             // Optional: "web" (default) or "device"
  "deviceId": 123                  // Optional: device ID for IoT clients
}
```

**Response (200 OK):**
```json
{
  "ticket": "abc123def456-uuid",
  "sessionId": "xyz789-session-uuid",
  "expiresIn": 60,
  "houseId": 1
}
```

**Errors:**
- `401 Unauthorized` - Missing or invalid JWT
- `403 Forbidden` - User doesn't have access to house
- `404 Not Found` - House or device not found
- `400 Bad Request` - Invalid request parameters

### WebSocket /ws/house/:houseId?ticket=TICKET

Connect to a house room via WebSocket.

**URL:**
```
wss://api.your-domain.com/ws/house/1?ticket=abc123def456-uuid
```

**Connection Flow:**
1. Client initiates WebSocket upgrade
2. Server validates ticket
3. Server checks ticket expiration
4. Server marks ticket as consumed
5. Server routes to HouseRoom Durable Object
6. Server sends `connected` message

**Example (JavaScript):**
```javascript
// 1. Get ticket from server
const ticketResponse = await fetch('https://api.your-domain.com/ws/ticket', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${jwtToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ houseId: 1, clientType: 'web' })
});

const { ticket, houseId } = await ticketResponse.json();

// 2. Connect to WebSocket
const ws = new WebSocket(`wss://api.your-domain.com/ws/house/${houseId}?ticket=${ticket}`);

ws.onopen = () => console.log('Connected to house room');
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};

ws.onerror = (error) => console.error('WebSocket error:', error);
ws.onclose = () => console.log('Disconnected from house room');
```

## Message Protocol

All messages are JSON objects with a required `type` field.

### Message Types

#### ping / pong (Keep-alive)

**Client → Server:**
```json
{
  "type": "ping",
  "requestId": "optional-request-id"
}
```

**Server → Client:**
```json
{
  "type": "pong",
  "timestamp": "2026-09-16T10:30:00Z",
  "requestId": "optional-request-id"
}
```

---

#### device_command (Web Client → Device)

Command from a web client to an IoT device.

**Message:**
```json
{
  "type": "device_command",
  "targetDeviceId": 123,
  "command": "unlock",
  "params": {
    "duration": 30
  }
}
```

**Fields:**
- `targetDeviceId` (required): Device ID to target
- `command` (required): Command name (e.g., "unlock", "lock", "toggle")
- `params` (optional): Command parameters

**Device receives:**
```json
{
  "type": "device_command",
  "command": "unlock",
  "params": { "duration": 30 },
  "fromUserId": 1,
  "fromSessionId": "session-uuid",
  "timestamp": "2026-09-16T10:30:00Z"
}
```

---

#### device_update (Device → Server)

Status update from an IoT device.

**Message:**
```json
{
  "type": "device_update",
  "deviceId": 123,
  "status": "online",
  "data": {
    "temperature": 22.5,
    "humidity": 45,
    "battery": 85
  }
}
```

**Fields:**
- `deviceId` (required): Device sending update
- `status` (optional): Device status ("online", "offline", etc.)
- `data` (optional): Device-specific data

**Web clients receive:**
```json
{
  "type": "device_update",
  "deviceId": 123,
  "status": "online",
  "data": { "temperature": 22.5, ... },
  "fromDeviceSessionId": "session-uuid",
  "timestamp": "2026-09-16T10:30:00Z"
}
```

---

#### get_devices (Request device list)

Request list of connected devices in the house.

**Message:**
```json
{
  "type": "get_devices"
}
```

**Response:**
```json
{
  "type": "devices_list",
  "devices": [
    {
      "deviceId": 123,
      "connectedAt": "2026-09-16T10:25:00Z",
      "lastMessageAt": "2026-09-16T10:30:00Z"
    },
    {
      "deviceId": 124,
      "connectedAt": "2026-09-16T10:20:00Z",
      "lastMessageAt": "2026-09-16T10:29:50Z"
    }
  ],
  "timestamp": "2026-09-16T10:30:00Z"
}
```

---

#### get_sessions (Admin only)

Request list of all connected sessions (admin users only).

**Message:**
```json
{
  "type": "get_sessions"
}
```

**Response (Admin only):**
```json
{
  "type": "sessions_list",
  "sessions": [
    {
      "sessionId": "session-uuid",
      "userId": 1,
      "clientType": "web",
      "deviceId": null,
      "role": "admin",
      "connectedAt": "2026-09-16T10:25:00Z",
      "lastMessageAt": "2026-09-16T10:30:00Z"
    }
  ],
  "timestamp": "2026-09-16T10:30:00Z"
}
```

---

#### System Messages (Server → Client)

**User joined:**
```json
{
  "type": "user_joined",
  "sessionId": "session-uuid",
  "userId": 1,
  "clientType": "web",
  "timestamp": "2026-09-16T10:30:00Z"
}
```

**User left:**
```json
{
  "type": "user_left",
  "sessionId": "session-uuid",
  "userId": 1,
  "clientType": "web",
  "timestamp": "2026-09-16T10:30:00Z"
}
```

**Connected (on initial connection):**
```json
{
  "type": "connected",
  "sessionId": "session-uuid",
  "houseId": 1,
  "message": "Connected to house room",
  "timestamp": "2026-09-16T10:30:00Z"
}
```

**Error:**
```json
{
  "type": "error",
  "error": "Device not connected",
  "timestamp": "2026-09-16T10:30:00Z"
}
```

---

#### Command Routed (Confirmation)

Server confirms command was routed to device:

```json
{
  "type": "command_routed",
  "targetDeviceId": 123,
  "command": "unlock",
  "timestamp": "2026-09-16T10:30:00Z"
}
```

## Client Implementation Examples

### Web Client (JavaScript)

```javascript
class HouseRoomClient {
  constructor(jwtToken, houseId, onMessage) {
    this.jwtToken = jwtToken;
    this.houseId = houseId;
    this.onMessage = onMessage;
    this.ws = null;
    this.pingInterval = null;
  }

  async connect() {
    // Get ticket
    const response = await fetch('/ws/ticket', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.jwtToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ houseId: this.houseId, clientType: 'web' })
    });

    if (!response.ok) {
      throw new Error('Failed to get WebSocket ticket');
    }

    const { ticket } = await response.json();

    // Connect
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    this.ws = new WebSocket(`${protocol}://${window.location.host}/ws/house/${this.houseId}?ticket=${ticket}`);

    this.ws.onopen = () => {
      console.log('Connected to house room');
      this.startPingInterval();
    };

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      this.onMessage(message);
    };

    this.ws.onerror = (error) => console.error('WebSocket error:', error);
    this.ws.onclose = () => {
      console.log('Disconnected');
      this.stopPingInterval();
    };
  }

  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  sendCommand(deviceId, command, params = {}) {
    this.send({
      type: 'device_command',
      targetDeviceId: deviceId,
      command,
      params
    });
  }

  getConnectedDevices() {
    this.send({ type: 'get_devices' });
  }

  startPingInterval() {
    this.pingInterval = setInterval(() => {
      this.send({ type: 'ping' });
    }, 30000); // Every 30 seconds
  }

  stopPingInterval() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
    }
  }

  disconnect() {
    this.stopPingInterval();
    if (this.ws) {
      this.ws.close();
    }
  }
}

// Usage
const client = new HouseRoomClient(jwtToken, 1, (message) => {
  console.log('Message:', message);
  
  if (message.type === 'device_update') {
    console.log(`Device ${message.deviceId} updated:`, message.data);
  }
});

await client.connect();

// Send command to device
client.sendCommand(123, 'unlock', { duration: 30 });

// Get list of devices
client.getConnectedDevices();

// Disconnect
client.disconnect();
```

### IoT Device (Node.js / ESP32)

```javascript
// ESP32 / Device client

class DeviceClient {
  constructor(deviceId, houseId, deviceToken) {
    this.deviceId = deviceId;
    this.houseId = houseId;
    this.deviceToken = deviceToken; // Device's JWT or API key
    this.ws = null;
  }

  async connect() {
    // Get ticket (using device token)
    const response = await fetch('https://api.domain.com/ws/ticket', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.deviceToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        houseId: this.houseId,
        clientType: 'device',
        deviceId: this.deviceId
      })
    });

    const { ticket } = await response.json();

    // Connect
    this.ws = new WebSocket(`wss://api.domain.com/ws/house/${this.houseId}?ticket=${ticket}`);

    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      this.handleMessage(message);
    };
  }

  handleMessage(message) {
    if (message.type === 'device_command') {
      console.log(`Command: ${message.command}`, message.params);
      
      // Execute command (device-specific)
      switch (message.command) {
        case 'unlock':
          this.executeUnlock(message.params);
          break;
        case 'lock':
          this.executeLock(message.params);
          break;
      }
    }
  }

  executeUnlock(params) {
    console.log('Unlocking...');
    // Device-specific unlock logic
    // GPIO, relay, etc.
    
    // Send update back
    this.sendUpdate({
      status: 'online',
      data: { locked: false }
    });
  }

  executeLock(params) {
    console.log('Locking...');
    // Device-specific lock logic
    
    this.sendUpdate({
      status: 'online',
      data: { locked: true }
    });
  }

  sendUpdate(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'device_update',
        deviceId: this.deviceId,
        ...data
      }));
    }
  }
}

// Usage
const device = new DeviceClient(123, 1, 'device-jwt-token');
await device.connect();
```

## Database Schema

### Required Tables

See `migrations/0002_smartroom.sql` for complete schema.

**houses** - House records
```sql
id, name, location, owner_id, created_at
```

**devices** - IoT devices in houses
```sql
id, house_id, device_name, device_type, device_id_external, status, created_at
```

**user_house_access** - User permissions
```sql
id, user_id, house_id, access_level, created_at
```

**websocket_tickets** - Short-lived authentication tickets
```sql
id, ticket_id, user_id, house_id, client_type, device_id, 
expires_at, consumed, created_at
```

## Security Checklist

- ✓ JWT-based authentication on ticket endpoint
- ✓ Ticket validation before WebSocket connection
- ✓ Ticket expiration (60 seconds)
- ✓ Single-use tickets (marked consumed)
- ✓ House ID validation
- ✓ User permission checks
- ✓ Device ID validation
- ✓ Client type validation (web/device)
- ✓ No query parameter authentication bypass
- ✓ Secure session metadata (not from client)
- ✓ WebSocket connection requires valid ticket
- ✓ Role-based access (admin can see all sessions)
- ✓ Graceful error messages (no leaking internals)

## Troubleshooting

### Ticket Validation Fails

**Problem:** "Ticket not found" or "Ticket already used"

**Causes:**
- Ticket expired (60 second limit)
- Ticket already used
- Wrong houseId in URL

**Solution:**
- Get a new ticket from `/ws/ticket` endpoint
- Ensure URL house ID matches ticket house ID

### "Device not connected"

**Problem:** Command to device fails

**Solution:**
- Check if device is connected: `get_devices` message
- Ensure device has active WebSocket session
- Check device ID is correct

### Permission Denied

**Problem:** "Access denied to this house"

**Solution:**
- Verify user has permission for house
- Check `user_house_access` table
- Admin users have access to all houses

### WebSocket connection drops

**Problem:** Connection closes unexpectedly

**Causes:**
- Inactivity timeout (5 minutes)
- Network interruption
- Server restart

**Solution:**
- Implement automatic reconnection
- Send ping/pong to keep alive
- Store last message ID for recovery

## Performance Notes

### Durable Objects
- One Durable Object instance per house
- Lightweight (minimal memory per session)
- WebSocket hibernation reduces CPU usage

### Scalability
- Horizontal scaling via multiple Worker instances
- Durable Objects automatically coordinate
- Database indexes on key fields

### Limits
- Max connections per Durable Object: Limited by Workers runtime
- Max message size: 256 KB (WebSocket standard)
- Max session duration: Indefinite (until close/disconnect)

## Future Enhancements

- [ ] Message history (last N messages per room)
- [ ] File transfer support
- [ ] Video stream integration
- [ ] Device discovery protocol
- [ ] Automatic device registration
- [ ] Advanced permission levels
- [ ] Audit logging per house
- [ ] Message encryption
- [ ] Presence indicators
- [ ] Typing indicators

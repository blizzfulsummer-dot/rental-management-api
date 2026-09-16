# Frontend Testing Guide

## Quick Start

### 1. Start the Development Server

```bash
npm run dev
```

This will start:
- Local Cloudflare Worker on `http://localhost:8787`
- Frontend accessible at `http://localhost:8787/`
- D1 database with migrations auto-applied

### 2. Access the Frontend

Open your browser:
```
http://localhost:8787/
```

### 3. Login with Demo Credentials

```
Email: admin@example.com
Password: AdminPass123!
```

## Frontend Features

### Login Screen
- Simple email/password login
- Pre-filled demo credentials
- Error messages displayed
- Loading state during login

### Dashboard Screen
Once logged in, you'll see:

#### Connection Status
- 🔴 Disconnected → 🟢 Connected (real-time indicator)
- Shows WebSocket connection status
- Displays session ID

#### Activity Log
- Real-time messages from WebSocket
- System messages (joined, connected, etc.)
- Device updates
- Error messages
- Timestamps for each message

#### Devices Grid
Shows all connected devices in the house with:
- Device name and type
- Online/offline status
- Last update time
- Turn ON/OFF buttons (sends commands)

## Testing Workflow

### Basic Flow

```
1. Navigate to http://localhost:8787/
2. Click "Sign In" (credentials pre-filled)
3. Wait for dashboard to load
4. Check Activity Log for connection messages
5. You should see connection and device list messages
6. Devices will appear in the grid
```

### Device Commands

```
1. Look for devices in the grid
2. Click "Turn ON" or "Turn OFF"
3. Check Activity Log for command confirmation
4. Message will show "Command sent to [device name]"
```

### WebSocket Flow (What's Happening)

```
Login
  ↓
POST /api/login (username + password)
  ↓ Receive JWT token
POST /ws/ticket (JWT + houseId=1)
  ↓ Receive short-lived ticket (60 seconds)
WebSocket /ws/house/1?ticket=...
  ↓
Receive "connected" message
  ↓
Auto-request device list
  ↓
Display devices and listen for updates
```

## Testing Without Devices

Even without real IoT devices connected, you can test:

1. **Login** - Tests authentication
2. **Ticket System** - Tests `/ws/ticket` endpoint
3. **WebSocket Connection** - Tests connection to HouseRoom Durable Object
4. **Empty Device List** - Shows "No Devices" message (normal)
5. **Activity Log** - Tracks all system messages
6. **UI Responsiveness** - Full dashboard UI works

## Terminal Testing (Optional)

### Get JWT Token
```bash
curl -X POST http://localhost:8787/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "AdminPass123!"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

### Get WebSocket Ticket
```bash
curl -X POST http://localhost:8787/ws/ticket \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "houseId": 1,
    "clientType": "web"
  }'
```

Response:
```json
{
  "ticket": "abc123...",
  "sessionId": "550e8400-...",
  "expiresIn": 60,
  "houseId": 1
}
```

### Connect with WebSocket (wscat)
```bash
# Install wscat globally (if not already)
npm install -g wscat

# Connect
wscat -c "ws://localhost:8787/ws/house/1?ticket=YOUR_TICKET"

# Send ping
{"type":"ping"}

# Get devices
{"type":"get_devices"}

# Send command
{"type":"device_command","deviceId":1,"command":"on"}
```

## Expected Messages

### Upon Connection
```json
{
  "type": "connected",
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "houseId": 1,
  "message": "Connected to house room",
  "timestamp": "2026-09-16T14:30:45.123Z"
}
```

### System Notifications
```json
{
  "type": "user_joined",
  "sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "userId": 1,
  "clientType": "web",
  "timestamp": "2026-09-16T14:30:45.123Z"
}
```

### Device List
```json
{
  "type": "get_devices",
  "devices": [
    {
      "id": 1,
      "house_id": 1,
      "device_name": "Living Room Light",
      "device_type": "light",
      "status": "online",
      "created_at": "2026-09-15T10:00:00Z"
    }
  ]
}
```

### Device Update
```json
{
  "type": "device_update",
  "deviceId": 1,
  "deviceName": "Living Room Light",
  "status": "on",
  "timestamp": "2026-09-16T14:30:45.123Z"
}
```

## Troubleshooting

### "Connection failed" error
- Check if `npm run dev` is running
- Check browser console (F12 → Console tab)
- Verify JWT is valid
- Check wrangler logs: `wrangler tail`

### "Invalid ticket" error
- Ticket expires after 60 seconds, need to login again
- Ensure houseId matches (default is 1)
- Check if ticket was already used

### WebSocket closes immediately
- Check houseId parameter is valid
- Verify ticket exists and is not consumed
- Check Durable Objects binding in wrangler.jsonc

### No devices appear
- This is normal! No devices are connected by default
- Create test devices in database or connect IoT device
- See next section for adding test data

### "No assets binding" warning
- This is OK during development
- Frontend still loads, just without caching benefits
- Production deployment will use assets properly

## Adding Test Devices (Database)

To add test devices to see them in the dashboard:

```bash
# Connect to database
wrangler d1 execute rental-db --local

# Insert test device
INSERT INTO devices (house_id, device_name, device_type, device_id_external, status)
VALUES (1, 'Living Room Light', 'light', 'device-001', 'online');

INSERT INTO devices (house_id, device_name, device_type, device_id_external, status)
VALUES (1, 'Bedroom Thermostat', 'thermostat', 'device-002', 'online');
```

Then refresh the dashboard - devices should appear!

## Next Steps

### Test Scenarios

1. **Login Test** ✓
   - Open browser
   - Login with credentials
   - Verify dashboard loads

2. **WebSocket Connection Test** ✓
   - Watch Activity Log
   - Should see "Ticket issued"
   - Should see "WebSocket connected"
   - Should see "Joined house room"

3. **Device Command Test**
   - Add test devices (see above)
   - Click device buttons
   - Check Activity Log for confirmations

4. **Multiple Clients Test**
   - Open two browser tabs
   - Login with same user in both
   - See "user_joined" messages in Activity Log
   - Send command from one tab, verify in other

5. **Ticket Expiration Test**
   - Login and get ticket
   - Wait 60+ seconds without connecting
   - Try to connect
   - Should see "Invalid ticket" error
   - Refresh and login again

## Performance Notes

- Handles multiple concurrent connections per house
- Activity Log shows last 50 messages (auto-trims)
- Devices grid updates in real-time
- Responsive design for mobile testing

## Security Notes (This is a Test Frontend!)

⚠️ **For Development Only**:
- Pre-filled credentials in login form (remove in production)
- WebSocket URL visible in browser (tickets are short-lived, this is OK)
- No HTTPS in local dev (use HTTPS in production)
- No rate limiting on frontend (backend has rate limiting)

## Support

See main documentation:
- [WebSocket Protocol](../docs/08-WEBSOCKET.md)
- [WebSocket Setup](../docs/09-WEBSOCKET_SETUP.md)
- [Security Guide](../docs/05-SECURITY.md)

# Smart Home WebSocket System - Complete Testing Guide

## Overview

This guide walks you through testing the complete smart home WebSocket system with:
1. **Frontend Dashboard** - Web UI for users to control devices
2. **Device Simulator** - Simulated IoT device for testing
3. **Real-time Communication** - Messages flowing between web and device

## Quick Start (5 minutes)

### Step 1: Start the Server

```bash
npm run dev
```

Wait for output:
```
⛅ wrangler dev
 ⛅ Using vars from .env
 ⛅ Listening on http://localhost:8787
```

### Step 2: Open Frontend

Open browser:
```
http://localhost:8787/
```

You should see the Smart Home login page.

### Step 3: Login

Click "Sign In" (credentials are pre-filled):
```
Email: admin@example.com
Password: AdminPass123!
```

You'll see:
- Connection status: 🔴 Disconnected → 🟢 Connected
- Activity log showing connection messages
- Empty device list (no devices yet)

### Step 4: Start Device Simulator (New Terminal)

```bash
# Install ws module first
npm install

# Run simulator
node device-simulator.js
```

You should see:
```
[2026-09-16T14:30:45.123Z] [SUCCESS] ✓ WebSocket connected
[2026-09-16T14:30:45.456Z] [WS] Sending initial device status...
```

### Step 5: Refresh Frontend

Go back to browser and refresh or wait for device list to appear.

You should now see:
- Device card appears in dashboard
- Device status shows as online
- Can click "Turn ON" / "Turn OFF" buttons

### Step 6: Test Full Communication

**Send command from web to device:**
1. Click "Turn ON" button on device card
2. Check terminal running device simulator
3. Should see: `📥 Received command: on`
4. Device status should update

**See device status updates in web:**
1. Device simulator sends periodic status every 30 seconds
2. Or simulator sends update after command
3. Browser Activity Log shows device updates

---

## Detailed Testing Scenarios

### Scenario 1: Login Flow ✓

**Expected Flow:**
```
1. Page loads with login form
2. Enter credentials (or use pre-filled)
3. Click "Sign In"
4. Activity Log shows: "Logged in as admin@example.com"
5. Dashboard loads with connecting status
6. Status updates to "Connected"
```

**Verify:**
- [ ] Login succeeds with correct credentials
- [ ] "Invalid credentials" error on wrong password
- [ ] Dashboard appears after successful login
- [ ] Connection indicator shows progress

### Scenario 2: WebSocket Ticket System ✓

**What's Happening:**
```
1. Frontend gets JWT from /api/login
2. Frontend exchanges JWT for ticket via /ws/ticket
3. Ticket is valid for 60 seconds only
4. Ticket is single-use
5. Frontend connects to WebSocket with ticket
```

**Verify in Activity Log:**
- [ ] "Logged in as..." message
- [ ] "Ticket issued (expires in 60s)" message
- [ ] "Connecting to house room..." message
- [ ] "✓ WebSocket connected!" message
- [ ] "✓ Joined house room" message

### Scenario 3: Device Connection ✓

**Setup:**
- Dashboard open and connected
- Device simulator running

**What Happens:**
```
Device Simulator:
1. Gets JWT (admin login simulated)
2. Exchanges for ticket (clientType: device)
3. Connects to same house room
4. Sends initial status update

Frontend:
1. Receives "user_joined" (device connected)
2. Activity Log shows device joined
3. Receives device_update with status
4. Device card appears in grid
5. Shows device as "Online"
```

**Verify:**
- [ ] Device simulator connects successfully
- [ ] Frontend Activity Log shows "Device joined"
- [ ] Device card appears with correct name
- [ ] Status shows "🟢 Online"
- [ ] Last Update shows recent timestamp

### Scenario 4: Send Device Commands ✓

**Setup:**
- Device simulator connected
- Device visible in dashboard

**Send Command from Frontend:**
1. Click "Turn ON" button on device card
2. Activity Log shows: "📤 Sent 'on' command to [device]"
3. WebSocket message sent: `{type: "device_command", deviceId: 1, command: "on"}`

**Device Receives and Responds:**
1. Simulator terminal shows: `📥 Received command: on`
2. Simulator updates status to "on"
3. Simulator sends `device_update` message back
4. Frontend Activity Log shows: "📊 Device: on"
5. Device card updates to show new status

**Verify:**
- [ ] Command sent successfully
- [ ] Device simulator receives command
- [ ] Device status updates
- [ ] Frontend shows new device status
- [ ] Activity Log shows all steps

### Scenario 5: Multiple Sessions ✓

**Setup:**
- Device simulator connected
- Dashboard already open

**Test:**
1. Open second browser tab: `http://localhost:8787/`
2. Login as same user (admin@example.com)
3. Both tabs should connect to same house room
4. Send command from one tab
5. Other tab should see the device update

**Verify:**
- [ ] Both tabs can login independently
- [ ] Both connect to WebSocket successfully
- [ ] Each shows "user_joined" for the other
- [ ] Commands from one tab affect device
- [ ] Other tab sees device updates
- [ ] Activity Logs show interaction

### Scenario 6: Ticket Expiration ✓

**Setup:**
- Dashboard open and connected

**Test:**
1. Wait 60 seconds
2. Close and reopen frontend tab
3. Try to login again

**Verify:**
- [ ] Old session eventually disconnects
- [ ] Can login and get new ticket
- [ ] Connection re-established successfully

### Scenario 7: Connection Persistence ✓

**Setup:**
- Device simulator running
- Dashboard connected

**Test:**
1. Let system run for 2+ minutes
2. Watch periodic status updates
3. Stop and restart device simulator

**Verify:**
- [ ] Device sends updates every 30 seconds
- [ ] Timestamps update in Activity Log
- [ ] When simulator stops: "user left" message
- [ ] When simulator restarts: "user joined" message
- [ ] Devices reappear after reconnection

---

## Terminal/API Testing

If you prefer testing via command line:

### 1. Get JWT Token

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
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

### 2. Get WebSocket Ticket

```bash
JWT="YOUR_TOKEN_HERE"

curl -X POST http://localhost:8787/ws/ticket \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "houseId": 1,
    "clientType": "web"
  }'
```

Response:
```json
{
  "ticket": "550e8400-e29b-41d4-a716-446655440000",
  "sessionId": "12345678-1234-1234-1234-123456789012",
  "expiresIn": 60,
  "houseId": 1
}
```

### 3. Test WebSocket with wscat

Install wscat:
```bash
npm install -g wscat
```

Connect:
```bash
TICKET="YOUR_TICKET_HERE"
wscat -c "ws://localhost:8787/ws/house/1?ticket=$TICKET"
```

Send messages:
```
# Ping
{"type":"ping"}

# Get devices
{"type":"get_devices"}

# Get sessions (admin only)
{"type":"get_sessions"}

# Send command
{"type":"device_command","deviceId":1,"command":"on"}
```

---

## Database Testing

### View All Devices

```bash
wrangler d1 execute rental-db --local -- "SELECT * FROM devices"
```

### Add Test Devices

```bash
wrangler d1 execute rental-db --local
```

Then run:
```sql
INSERT INTO devices (house_id, device_name, device_type, device_id_external, status)
VALUES 
  (1, 'Living Room Light', 'light', 'device-001', 'online'),
  (1, 'Kitchen Thermostat', 'thermostat', 'device-002', 'online'),
  (1, 'Front Door Lock', 'lock', 'device-003', 'offline');
```

### View User Access

```bash
wrangler d1 execute rental-db --local -- "SELECT * FROM user_house_access"
```

---

## Device Simulator Options

Run with custom configuration:

```bash
# Custom device
DEVICE_ID=2 DEVICE_NAME="Kitchen Light" node device-simulator.js

# Multiple simulators (different terminals)
DEVICE_ID=1 DEVICE_NAME="Device 1" node device-simulator.js
DEVICE_ID=2 DEVICE_NAME="Device 2" node device-simulator.js
DEVICE_ID=3 DEVICE_NAME="Device 3" node device-simulator.js
```

### Environment Variables

```bash
API_URL              # Base API URL (default: http://localhost:8787)
WS_URL               # WebSocket base URL (default: ws://localhost:8787)
DEVICE_ID            # Device ID to simulate (default: 1)
DEVICE_TYPE          # Device type (default: light)
DEVICE_NAME          # Display name (default: Simulated Device)
HOUSE_ID             # House ID (default: 1)
DEVICE_API_KEY       # API key for device auth (default: demo)
SIMULATE_COMMANDS    # Respond to commands (default: true)
```

---

## Monitoring & Debugging

### Browser Console

Open DevTools (F12) and check:
- **Console** - JavaScript errors
- **Network** - API calls and WebSocket
- **Application** → Local Storage - Check for stored tokens

### Wrangler Logs

```bash
# In separate terminal, watch logs
wrangler tail
```

Shows:
- Worker logs
- Errors
- Performance metrics

### Device Simulator Output

The device simulator shows:
- Connection attempts
- Sent/received messages
- Status updates
- Command handling

---

## Common Issues & Solutions

### Issue: "Connection failed"

**Causes:**
- Server not running (`npm run dev`)
- Browser firewall/proxy blocking WebSocket

**Solution:**
```bash
# Restart server
npm run dev

# Check it's listening
curl http://localhost:8787/

# Try different port
PORT=8788 npm run dev
```

### Issue: "Invalid ticket"

**Causes:**
- Ticket expired (60 second limit)
- Ticket already used
- Wrong house ID

**Solution:**
- Login again to get new ticket
- Ensure houseId=1 is used
- Check wrangler logs: `wrangler tail`

### Issue: Device not appearing

**Causes:**
- Device simulator crashed
- No devices in database
- Device connected to different house

**Solution:**
1. Check device simulator is running
2. Add test devices to database
3. Verify HOUSE_ID matches (default: 1)
4. Refresh browser
5. Check wrangler logs

### Issue: Commands not working

**Causes:**
- Device simulator exited
- SIMULATE_COMMANDS=false

**Solution:**
1. Restart device simulator
2. Set SIMULATE_COMMANDS=true (default)
3. Check both are on same house

---

## Performance Testing

### Load Test: Many Devices

```bash
# Spawn 10 device simulators
for i in {1..10}; do
  DEVICE_ID=$i DEVICE_NAME="Device $i" node device-simulator.js &
done
```

Monitor:
- Browser dashboard loads all devices
- Activity Log handles rapid updates
- No connection drops

### Load Test: Many Clients

```bash
# Terminal 1: Device simulator
node device-simulator.js

# Terminal 2-5: Open frontend in multiple browser windows
# Send commands from different windows
# Watch Activity Log for all interactions
```

Monitor:
- All clients receive updates
- Commands route correctly
- No message loss

---

## Checklist: Full System Test

- [ ] Server starts without errors (`npm run dev`)
- [ ] Frontend loads at `http://localhost:8787/`
- [ ] Can login with demo credentials
- [ ] Dashboard connects to WebSocket
- [ ] Connection status updates to "Connected"
- [ ] Can logout successfully
- [ ] Device simulator connects as device
- [ ] Device appears in dashboard grid
- [ ] Can send "Turn ON" command
- [ ] Device simulator receives command
- [ ] Device status updates on frontend
- [ ] Multiple browser tabs work simultaneously
- [ ] Activity Log shows all events
- [ ] Periodic status updates appear
- [ ] No console errors (F12 to check)
- [ ] Wrangler logs show requests
- [ ] Can reconnect after disconnect
- [ ] Can run multiple device simulators

---

## Next Steps

After basic testing works:

1. **Add more devices** - Insert into database, test with multiple
2. **Customize messages** - Modify houseRoom.js for your device types
3. **Implement real auth** - Replace admin login simulation
4. **Add persistence** - Store message history
5. **Deploy to production** - Follow deployment guide
6. **Build real device** - Use Arduino/ESP32 with WebSocket client
7. **Add monitoring** - Track errors and performance

---

## Getting Help

**Documentation Files:**
- `docs/08-WEBSOCKET.md` - Protocol details
- `docs/09-WEBSOCKET_SETUP.md` - Integration guide
- `docs/05-SECURITY.md` - Security best practices

**Common Questions:**

**Q: Can I run multiple device simulators?**  
A: Yes! Each can connect to same house or different houses. See "Load Testing" section above.

**Q: How do I add real IoT devices?**  
A: See `docs/09-WEBSOCKET_SETUP.md` for device authentication options.

**Q: Is the frontend production-ready?**  
A: No - it's for testing. Pre-filled credentials and no HTTPS. Customize for production.

**Q: How do I customize messages?**  
A: Edit `src/houseRoom.js` to add message types. See "Customization" in `WEBSOCKET_INTEGRATION_SUMMARY.md`.

---

**Happy Testing! 🚀**

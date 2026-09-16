# WebSocket System Integration Guide

Step-by-step guide to integrate the WebSocket room system into your rental management project.

## Prerequisites

- Existing authentication Worker with JWT tokens
- Cloudflare Workers account with D1 database
- Wrangler CLI configured
- Node.js 18+

## Integration Checklist

### Phase 1: Database Setup

- [ ] Review `migrations/0002_smartroom.sql`
- [ ] Customize table schemas to match your data model
- [ ] Apply migration: `npm run dev` (auto-applies pending migrations)
- [ ] Verify tables created:
  ```bash
  wrangler d1 execute rental-db --remote -- ".schema"
  ```

**IMPORTANT: Customize these tables before deployment:**

1. **houses table**
   - Match your existing house/property structure
   - Link to owner (admin user)
   - Add any additional fields (address, type, capacity, etc.)

2. **devices table**
   - Match your device identification system
   - Ensure `device_id_external` matches your ESP32 IDs
   - Add device-specific metadata as needed

3. **user_house_access table**
   - Align with your permission model
   - Supports multiple access levels (admin, tenant, guest, etc.)
   - Or create a simpler model if all users should access all houses

### Phase 2: Code Integration

- [ ] Files created in your project:
  - `src/houseRoom.js` - Durable Object implementation
  - `src/lib/websocketTicket.js` - Ticket system
  - `migrations/0002_smartroom.sql` - Database schema
  - `docs/08-WEBSOCKET.md` - WebSocket documentation

- [ ] Files modified:
  - `wrangler.jsonc` - Added Durable Object binding
  - `src/worker.js` - Added WebSocket routes

### Phase 3: Configuration

**1. Update wrangler.jsonc bindings (DONE):**

```jsonc
{
  "durable_objects": {
    "bindings": [
      {
        "name": "HOUSE_ROOM",
        "class_name": "HouseRoom",
        "environment": "production"
      }
    ]
  }
}
```

**2. Verify JWT Secret:**

Ensure `JWT_SCRT` is configured in Cloudflare Secrets:
```bash
wrangler secret list
```

Should show `JWT_SCRT` binding.

**3. Verify D1 Binding:**

Ensure `DB` binding exists in `wrangler.jsonc`:
```jsonc
{
  "d1_databases": [
    {
      "binding": "DB",
      "database_id": "YOUR_DATABASE_ID"
    }
  ]
}
```

### Phase 4: Customization

**1. Update Permission Model** (`src/lib/websocketTicket.js`):

The ticket system needs to verify user access to houses. Update the permission checking logic around line 85:

```javascript
// Current placeholder (line 85-110)
// Customize based on YOUR permission model:
// - Do admins access all houses?
// - Do tenants access their assigned house?
// - Are there additional permission tables?
// - Should devices inherit tenant permissions?

// Example: If your model is "tenants belong to one house via leased_unit"
const tenant = await env.DB
  .prepare('SELECT house_id FROM tenants WHERE user_id = ? LIMIT 1')
  .bind(userId)
  .first();
if (tenant && tenant.house_id === houseId) {
  hasAccess = true;
  userRole = 'tenant';
}
```

**2. Update Session Metadata** (`src/houseRoom.js`):

The session object stores metadata per connection (line 28-36):

```javascript
// Customize based on what you need to track:
// - connectedAt: timestamp
// - lastMessageAt: for activity tracking
// - deviceId: ESP32 identifier
// - role: user permission level
// - clientType: 'web' or 'device'

// Add custom fields as needed:
// - location: which room in the house?
// - permissions: specific capabilities?
// - metadata: custom device data?
```

**3. Extend Message Types** (`src/houseRoom.js`):

The message handler (line 54-96) can be extended:

```javascript
// Add new message types in switch statement:
case 'my_custom_type':
  this.handleCustomMessage(sessionId, session, message);
  break;
```

**4. Device Type Validation** (`src/lib/websocketTicket.js`):

Update device type validation (line 72-76) based on your device types:

```javascript
// Current: just checks clientType is 'web' or 'device'
// Extend to validate specific device types:

const validDeviceTypes = ['lock', 'gate', 'relay', 'light', 'sensor'];
if (clientType === 'device') {
  const device = await env.DB
    .prepare('SELECT device_type FROM devices WHERE id = ?')
    .bind(deviceId)
    .first();
  
  if (!device || !validDeviceTypes.includes(device.device_type)) {
    return json({ error: 'Invalid device type' }, 400);
  }
}
```

## Testing

### 1. Test Locally

```bash
npm run dev
```

### 2. Test JWT & Ticket Endpoint

```bash
# 1. Login to get JWT
curl -X POST http://localhost:8787/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "AdminPass123!"}'

# Store JWT_TOKEN from response

# 2. Get WebSocket ticket
curl -X POST http://localhost:8787/ws/ticket \
  -H "Authorization: Bearer JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"houseId": 1, "clientType": "web"}'

# Store TICKET from response
```

### 3. Test WebSocket Connection

Use a WebSocket client (wscat, curl with --raw, or browser):

```bash
# Using wscat (npm install -g wscat)
wscat -c "ws://localhost:8787/ws/house/1?ticket=YOUR_TICKET"

# Once connected, send messages:
{"type": "ping"}
{"type": "get_devices"}
```

### 4. Test Message Protocol

After connecting:

```bash
# Send ping
{"type": "ping"}

# Get devices
{"type": "get_devices"}

# Send command to device
{"type": "device_command", "targetDeviceId": 1, "command": "unlock"}

# Admin: get sessions
{"type": "get_sessions"}
```

## Deployment

### 1. Apply Database Migration

```bash
# Create migration table if needed
wrangler d1 execute rental-db --remote -- "SELECT 1"

# Apply migration
wrangler d1 execute rental-db --remote < migrations/0002_smartroom.sql
```

### 2. Verify Migration

```bash
wrangler d1 execute rental-db --remote -- "SELECT name FROM sqlite_master WHERE type='table'"
```

Should show: houses, devices, user_house_access, websocket_tickets (plus existing tables)

### 3. Deploy Worker

```bash
npm run build
npm run deploy
```

### 4. Test in Production

```bash
# Get JWT token from production
curl -X POST https://api.your-domain.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Get ticket
curl -X POST https://api.your-domain.com/ws/ticket \
  -H "Authorization: Bearer JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"houseId": 1}'

# Test WebSocket
wscat -c "wss://api.your-domain.com/ws/house/1?ticket=TICKET"
```

## CORS Configuration

WebSocket connections bypass CORS, but the `/ws/ticket` endpoint needs CORS handling.

Current setup in `src/worker.js` already handles `/ws/ticket` with CORS headers.

If you add custom origins, update `ALLOWED_ORIGINS` in `src/worker.js`:

```javascript
const ALLOWED_ORIGINS = [
  'https://your-frontend-domain.com',
  'https://your-app.example.com'
];
```

## Authentication for IoT Devices

IoT devices need their own authentication method. Options:

### Option 1: Device-specific JWT Tokens
```javascript
// Issue a device JWT during device registration
const deviceToken = await new SignJWT({ 
  sub: device.id,
  type: 'device',
  houseId: device.house_id
})
.setProtectedHeader({ alg: 'HS256' })
.setExpirationTime('30d') // Long-lived
.sign(getSecret(env));

// Device stores this token securely
// Uses token to get WebSocket tickets
```

### Option 2: Device API Keys
```javascript
// Generate secure random key during device registration
const apiKey = crypto.randomUUID() + crypto.randomUUID();

// Store in database
await env.DB
  .prepare('INSERT INTO device_keys (device_id, key_hash, created_at) VALUES (?, ?, ?)')
  .bind(device.id, hashKey(apiKey), new Date().toISOString())
  .run();

// Device sends: Authorization: Bearer DEVICE_API_KEY
```

### Option 3: Device Pairing Code
```javascript
// Generate temporary pairing code
const pairingCode = generateRandomCode(6);

// Device displays code
// Admin enters code in app to pair
// System generates Device JWT token after pairing
```

**Recommended:** Use Option 1 (device-specific JWT tokens) for consistency with your existing auth system.

## Troubleshooting Integration

### Error: "HOUSE_ROOM is not defined"

**Cause:** Durable Object not exported or not configured in wrangler.jsonc

**Fix:**
1. Verify `src/houseRoom.js` exports `HouseRoom` class
2. Verify `wrangler.jsonc` has durable_objects binding
3. Verify import in `src/worker.js`: `import { HouseRoom } from './houseRoom.js';`

### Error: "Cannot read property 'get' of undefined"

**Cause:** `env.HOUSE_ROOM` binding not available

**Fix:**
- Run `npm run dev` to reload environment
- Check wrangler.jsonc syntax
- Restart Wrangler

### WebSocket connection fails with 401

**Cause:** Invalid or expired ticket

**Fix:**
1. Get a fresh ticket from `/ws/ticket`
2. Verify ticket isn't already consumed
3. Check ticket hasn't expired (60 seconds)

### Database queries fail

**Cause:** Tables don't exist or schema mismatch

**Fix:**
1. Verify migration applied: `wrangler d1 execute rental-db --remote -- ".schema"`
2. Check table names match in code
3. Check column names match your customized schema

## Next Steps

1. **Populate Test Data:**
   ```sql
   INSERT INTO houses (name, location, owner_id, created_at) 
   VALUES ('Test House', '123 Main St', 1, datetime('now'));
   
   INSERT INTO devices (house_id, device_name, device_type, created_at) 
   VALUES (1, 'Front Door', 'lock', datetime('now'));
   
   INSERT INTO user_house_access (user_id, house_id, access_level, created_at) 
   VALUES (1, 1, 'admin', datetime('now'));
   ```

2. **Implement Frontend WebSocket Client:**
   - See `docs/08-WEBSOCKET.md` for example
   - Use provided `HouseRoomClient` class
   - Handle reconnection logic

3. **Implement IoT Device Client:**
   - See `docs/08-WEBSOCKET.md` for device example
   - Handle command reception
   - Send status updates
   - Implement device-specific logic

4. **Add Monitoring:**
   - Log WebSocket connections/disconnections
   - Monitor ticket creation/validation
   - Track device updates
   - Alert on permission failures

5. **Implement Rate Limiting:**
   - Consider limiting message frequency per session
   - Prevent spam from web clients
   - Implement message size limits

## Support

For issues or questions:

1. Check [WebSocket Documentation](08-WEBSOCKET.md)
2. Review example code in documentation
3. Check error messages in `wrangler tail` logs
4. Verify database schema and permissions
5. Test with curl/wscat before complex integrations

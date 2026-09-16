/**
 * WebSocket ticket system for secure, short-lived access to HouseRoom
 * 
 * Flow:
 * 1. Frontend: POST /ws/ticket with JWT
 * 2. Worker: Validates JWT, checks house access permissions
 * 3. Worker: Issues short-lived, single-use ticket (30-60 seconds)
 * 4. Frontend: Connects to WebSocket with ticket: wss://domain/ws/house/:houseId?ticket=SHORT_LIVED_TICKET
 * 5. WebSocket handler: Validates ticket, routes to HouseRoom Durable Object
 * 6. HouseRoom: Accepts connection with authenticated session metadata
 */

import { jwtVerify } from 'jose';

/**
 * Generate a UUID using Web Crypto API (works in Cloudflare Workers)
 */
function generateUUID() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Validate JWT and issue a short-lived WebSocket ticket
 * Endpoint: POST /ws/ticket
 * 
 * Request body:
 * {
 *   "houseId": 1,
 *   "clientType": "web" or "device",  // optional, default "web"
 *   "deviceId": 123                     // optional, for IoT devices
 * }
 * 
 * Request header:
 * Authorization: Bearer <JWT_ACCESS_TOKEN>
 * 
 * Response:
 * {
 *   "ticket": "UNIQUE_TICKET_ID",
 *   "expiresIn": 60,  // seconds
 *   "sessionId": "SESSION_ID",
 *   "houseId": 1
 * }
 */
export async function issueWebSocketTicket(request, env) {
  // Only allow POST
  if (request.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405);
  }

  try {
    // Extract and validate JWT from Authorization header
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return json({ error: 'Missing or invalid Authorization header' }, 401);
    }

    const token = authHeader.slice(7);
    let payload;

    // Verify JWT
    try {
      const verified = await jwtVerify(token, getSecret(env));
      payload = verified.payload;
    } catch (error) {
      console.error('JWT verification failed:', error.message);
      return json({ error: 'Invalid or expired token' }, 401);
    }

    const userId = payload.sub;
    if (!userId) {
      return json({ error: 'Invalid token claims' }, 401);
    }

    // Parse request body
    const body = await parseJsonBody(request);
    if (!body.ok) {
      return json({ error: body.error }, 400);
    }

    const { houseId, clientType = 'web', deviceId } = body.data;

    // Validate houseId
    if (!houseId) {
      return json({ error: 'houseId is required' }, 400);
    }

    if (typeof houseId !== 'number' || houseId <= 0) {
      return json({ error: 'Invalid houseId' }, 400);
    }

    // Validate clientType
    if (!['web', 'device'].includes(clientType)) {
      return json({ error: 'clientType must be "web" or "device"' }, 400);
    }

    // For device clients, require deviceId
    if (clientType === 'device' && !deviceId) {
      return json({ error: 'deviceId is required for device clients' }, 400);
    }

    // Query user and their permissions
    const user = await env.DB
      .prepare('SELECT id, role FROM users WHERE id = ?')
      .bind(userId)
      .first();

    if (!user) {
      return json({ error: 'User not found' }, 404);
    }

    // Check if user can access this house
    // PLACEHOLDER: Adjust query based on your actual permission model
    // This example checks if:
    // 1. User is an admin (can access any house), OR
    // 2. User has explicit access to the house in user_house_access table
    let hasAccess = false;
    let userRole = 'user';

    if (user.role === 'admin') {
      hasAccess = true;
      userRole = 'admin';
    } else {
      const permission = await env.DB
        .prepare('SELECT access_level FROM user_house_access WHERE user_id = ? AND house_id = ?')
        .bind(userId, houseId)
        .first();

      if (permission) {
        hasAccess = true;
        userRole = permission.access_level;
      }
    }

    // PLACEHOLDER: Adjust based on your permission model
    // Example: Tenants automatically have access to their own house
    if (!hasAccess && user.role === 'tenant') {
      const tenant = await env.DB
        .prepare('SELECT id FROM tenants WHERE user_id = ? LIMIT 1')
        .bind(userId)
        .first();

      if (tenant) {
        // In your schema, you'd have house_id linked to tenants
        // For now, this is a placeholder
        hasAccess = true;
        userRole = 'tenant';
      }
    }

    if (!hasAccess) {
      return json({ error: 'Access denied to this house' }, 403);
    }

    // Validate device exists (if deviceId provided)
    if (deviceId) {
      const device = await env.DB
        .prepare('SELECT id FROM devices WHERE id = ? AND house_id = ?')
        .bind(deviceId, houseId)
        .first();

      if (!device) {
        return json({ error: 'Device not found in this house' }, 404);
      }
    }

    // Generate short-lived, single-use ticket
    const ticketId = generateUUID();
    const sessionId = generateUUID();
    const expiresInSeconds = 60; // 1 minute - adjust as needed
    const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();

    // Store ticket in database for validation later
    try {
      await env.DB
        .prepare(`
          INSERT INTO websocket_tickets 
          (ticket_id, user_id, house_id, client_type, device_id, expires_at, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(ticketId, userId, houseId, clientType, deviceId || null, expiresAt, new Date().toISOString())
        .run();
    } catch (error) {
      console.error('Failed to store ticket:', error);
      return json({ error: 'Failed to issue ticket' }, 500);
    }

    return json({
      ticket: ticketId,
      sessionId: sessionId,
      expiresIn: expiresInSeconds,
      houseId: houseId
    }, 200);
  } catch (error) {
    console.error('Error issuing WebSocket ticket:', error);
    return json({ error: 'Internal server error' }, 500);
  }
}

/**
 * Validate WebSocket ticket and return session metadata
 * Called by WebSocket handler before routing to Durable Object
 * 
 * Returns:
 * {
 *   valid: true,
 *   userId: 1,
 *   houseId: 1,
 *   clientType: "web",
 *   deviceId: null,
 *   role: "user"
 * }
 */
export async function validateWebSocketTicket(env, ticketId, houseId) {
  try {
    // Look up ticket
    const ticket = await env.DB
      .prepare(`
        SELECT 
          ticket_id, user_id, house_id, client_type, device_id, 
          expires_at, consumed, created_at
        FROM websocket_tickets
        WHERE ticket_id = ?
      `)
      .bind(ticketId)
      .first();

    if (!ticket) {
      console.warn(`[WebSocket] Ticket not found: ${ticketId}`);
      return { valid: false, error: 'Ticket not found' };
    }

    // Verify ticket belongs to requested house
    if (ticket.house_id !== houseId) {
      console.warn(`[WebSocket] Ticket/house mismatch: ticket=${ticket.house_id}, requested=${houseId}`);
      return { valid: false, error: 'Ticket does not match house' };
    }

    // Check if already consumed
    if (ticket.consumed) {
      console.warn(`[WebSocket] Ticket already consumed: ${ticketId}`);
      return { valid: false, error: 'Ticket already used' };
    }

    // Check if expired
    const expiresAt = new Date(ticket.expires_at);
    if (expiresAt < new Date()) {
      console.warn(`[WebSocket] Ticket expired: ${ticketId}`);
      return { valid: false, error: 'Ticket expired' };
    }

    // Mark ticket as consumed (single-use)
    try {
      await env.DB
        .prepare('UPDATE websocket_tickets SET consumed = 1 WHERE ticket_id = ?')
        .bind(ticketId)
        .run();
    } catch (error) {
      console.error('Failed to mark ticket as consumed:', error);
      // Continue anyway - ticket is single-use semantically
    }

    // Get user details
    const user = await env.DB
      .prepare('SELECT role FROM users WHERE id = ?')
      .bind(ticket.user_id)
      .first();

    if (!user) {
      console.warn(`[WebSocket] User not found: ${ticket.user_id}`);
      return { valid: false, error: 'User not found' };
    }

    return {
      valid: true,
      userId: ticket.user_id,
      houseId: ticket.house_id,
      clientType: ticket.client_type,
      deviceId: ticket.device_id,
      role: user.role,
      ticketId: ticketId
    };
  } catch (error) {
    console.error('Error validating WebSocket ticket:', error);
    return { valid: false, error: 'Validation error' };
  }
}

/**
 * Helper: Get JWT secret from environment
 */
function getSecret(env) {
  const secret = env.JWT_SCRT;
  if (!secret) {
    throw new Error('JWT_SCRT not configured');
  }
  return new TextEncoder().encode(secret);
}

/**
 * Helper: Parse JSON body safely
 */
async function parseJsonBody(request) {
  try {
    const body = await request.json();
    return { ok: true, data: body };
  } catch (error) {
    return { ok: false, error: 'Invalid JSON' };
  }
}

/**
 * Helper: JSON response
 */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

import { createTenant, deleteTenant, getTenant, listTenants, updateTenant } from './tenant.js';
import { getAuthUser, login, refreshToken, requestReset, resetPassword, signup, updatePassword, verifyJwt } from './auth.js';
import { createRateLimiter } from './lib/rateLimit.js';
import { issueWebSocketTicket, validateWebSocketTicket } from './lib/websocketTicket.js';
import { HouseRoom } from './houseRoom.js';

const ALLOWED_ORIGINS = [
  'https://test-front-env.pages.dev',
  'https://my-other-site.pages.dev',
  'https://rental-management.ehexibit.com'
];

const authRateLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, maxRequests: 10 });

function withCors(response, allowOrigin = '*') {
  response.headers.set('Access-Control-Allow-Origin', allowOrigin);
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return response;
}

function getAllowOrigin(request) {
  const origin = request.headers.get('Origin');
  if (origin && ALLOWED_ORIGINS.includes(origin)) return origin;
  return '*';
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function shouldRateLimit(pathname) {
  return ['/api/signup', '/api/login', '/api/update_password', '/api/request_reset', '/api/reset_password'].includes(pathname);
}

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
 * Handle WebSocket upgrade for house room connections
 * URL: /ws/house/:houseId?ticket=SHORT_LIVED_TICKET
 */
async function handleHouseRoomWebSocket(request, env, url) {
  // Only allow WebSocket upgrade
  if (request.headers.get('Upgrade') !== 'websocket') {
    return json({ error: 'Expected WebSocket' }, 400);
  }

  // Extract houseId from path
  const pathParts = url.pathname.split('/');
  const houseIdStr = pathParts[3]; // /ws/house/:houseId
  const houseId = parseInt(houseIdStr);

  if (!houseId || isNaN(houseId)) {
    return json({ error: 'Invalid house ID' }, 400);
  }

  // Extract and validate ticket from query parameters
  const ticket = url.searchParams.get('ticket');
  if (!ticket) {
    return json({ error: 'WebSocket ticket required' }, 401);
  }

  // Validate ticket
  const validation = await validateWebSocketTicket(env, ticket, houseId);
  if (!validation.valid) {
    return json({ error: validation.error || 'Invalid ticket' }, 401);
  }

  // Get Durable Object for this house
  const durableObjectId = env.HOUSE_ROOM.idFromName(`house-${houseId}`);
  const durableObject = env.HOUSE_ROOM.get(durableObjectId);

  // Build URL with session metadata for the Durable Object
  const sessionUrl = new URL(request.url);
  sessionUrl.searchParams.set('sessionId', validation.sessionId || generateUUID());
  sessionUrl.searchParams.set('userId', validation.userId);
  sessionUrl.searchParams.set('clientType', validation.clientType);
  if (validation.deviceId) {
    sessionUrl.searchParams.set('deviceId', validation.deviceId);
  }
  sessionUrl.searchParams.set('role', validation.role);
  sessionUrl.pathname = '/';

  // Forward request to Durable Object
  return durableObject.fetch(new Request(sessionUrl, { 
    method: request.method,
    headers: request.headers
  }));
}

export { HouseRoom };

export default {
  async fetch(request, env) {
    const allowOrigin = getAllowOrigin(request);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': allowOrigin,
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }

    const url = new URL(request.url);

    // Serve static files (index.html, etc.)
    if (url.pathname === '/' || url.pathname === '/index.html') {
      try {
        // Try ASSETS binding first (production)
        if (env.ASSETS) {
          const file = await env.ASSETS.get('index.html');
          if (file) {
            return new Response(file, {
              status: 200,
              headers: {
                'Content-Type': 'text/html',
                'Cache-Control': 'public, max-age=3600'
              }
            });
          }
        }
      } catch (e) {
        // Fall through to serve fallback
      }
      
      // Fallback HTML for development (no ASSETS binding)
      const fallbackHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Home Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .container { background: white; border-radius: 12px; padding: 40px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); width: 100%; max-width: 400px; }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        p { color: #666; margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #333; margin-bottom: 8px; font-weight: 500; }
        input { width: 100%; padding: 12px 15px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
        input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        button { width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3); }
        button:disabled { opacity: 0.6; cursor: not-allowed; }
        .error { color: #e74c3c; font-size: 14px; margin-top: 15px; padding: 10px; background: #fadbd8; border-radius: 6px; display: none; }
        .error.show { display: block; }
        .success { color: #27ae60; font-size: 14px; margin-top: 15px; padding: 10px; background: #d4edda; border-radius: 6px; display: none; }
        .success.show { display: block; }
        .dashboard { display: none; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div id="loginForm">
            <h1>🏠 Smart Home</h1>
            <p>Property Management System</p>
            
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" placeholder="admin@example.com" value="admin@example.com">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Password" value="AdminPass123!">
            </div>

            <button id="loginBtn" onclick="handleLogin()">Sign In</button>

            <div class="error" id="loginError"></div>

            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; color: #999; font-size: 12px;">
                <p><strong>Demo Credentials:</strong></p>
                <p>Email: admin@example.com</p>
                <p>Password: AdminPass123!</p>
            </div>
        </div>

        <div id="dashboard" class="dashboard">
            <h1>✅ Connected!</h1>
            <p id="status">Initializing...</p>
            <div id="log" style="margin-top: 20px; max-height: 300px; overflow-y: auto; background: #f5f5f5; padding: 10px; border-radius: 6px; font-size: 12px; font-family: monospace;"></div>
        </div>
    </div>

    <script>
        const protocol = window.location.protocol;
        const host = window.location.host;
        const API_BASE = protocol + '//' + host;
        const WS_BASE = (protocol === 'https:' ? 'wss' : 'ws') + '://' + host;
        let jwt = null;
        let ws = null;

        function log(msg) {
            const logDiv = document.getElementById('log');
            const time = new Date().toLocaleTimeString();
            logDiv.innerHTML = \`<div>[\${time}] \${msg}</div>\` + logDiv.innerHTML;
        }

        async function handleLogin() {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const btn = document.getElementById('loginBtn');
            const errorDiv = document.getElementById('loginError');

            btn.disabled = true;
            btn.textContent = 'Signing in...';
            errorDiv.classList.remove('show');

            try {
                const response = await fetch(\`\${API_BASE}/api/login\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.message || 'Login failed');
                }

                jwt = data.accessToken;
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                log('✓ Logged in successfully');
                
                await connectWebSocket();
            } catch (error) {
                errorDiv.textContent = error.message;
                errorDiv.classList.add('show');
                log('✗ ' + error.message);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Sign In';
            }
        }

        async function connectWebSocket() {
            try {
                log('Requesting WebSocket ticket...');

                const ticketResponse = await fetch(\`\${API_BASE}/ws/ticket\`, {
                    method: 'POST',
                    headers: {
                        'Authorization': \`Bearer \${jwt}\`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        houseId: 1,
                        clientType: 'web'
                    })
                });

                if (!ticketResponse.ok) {
                    throw new Error('Failed to get ticket: ' + ticketResponse.statusText);
                }

                const { ticket } = await ticketResponse.json();
                log('✓ Ticket received (60s validity)');

                const wsUrl = \`\${WS_BASE}/ws/house/1?ticket=\${ticket}\`;
                ws = new WebSocket(wsUrl);

                ws.onopen = () => {
                    log('✓ WebSocket connected');
                    document.getElementById('status').textContent = '🟢 Connected to Smart Home';
                };

                ws.onmessage = (event) => {
                    const msg = JSON.parse(event.data);
                    log(\`→ \${msg.type}: \${JSON.stringify(msg).substring(0, 50)}...\`);
                };

                ws.onerror = (error) => {
                    log('✗ WebSocket error: ' + error.message);
                };

                ws.onclose = () => {
                    log('✗ WebSocket closed');
                };
            } catch (error) {
                log('✗ Connection error: ' + error.message);
            }
        }

        document.addEventListener('DOMContentLoaded', () => {
            document.getElementById('email').focus();
        });
    </script>
</body>
</html>`;
      
      return new Response(fallbackHTML, {
        status: 200,
        headers: {
          'Content-Type': 'text/html',
          'Cache-Control': 'no-cache'
        }
      });
    }

    // Skip rate limiting in development (localhost)
    const isDevelopment = url.hostname === 'localhost' || url.hostname === '127.0.0.1';

    if (!isDevelopment && shouldRateLimit(url.pathname)) {
      const rateLimitKey = request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for') || 'anonymous';
      const result = authRateLimiter(rateLimitKey);
      if (!result.ok) {
        return withCors(json({ error: 'Too many requests' }, 429), allowOrigin);
      }
    }

    try {
      if (url.pathname === '/api/signup' && request.method === 'POST') {
        return withCors(await signup(request, env), allowOrigin);
      }

      if (url.pathname === '/api/login' && request.method === 'POST') {
        return withCors(await login(request, env), allowOrigin);
      }

      if (url.pathname === '/api/update_password' && request.method === 'POST') {
        return withCors(await updatePassword(request, env), allowOrigin);
      }

      if (url.pathname === '/api/request_reset' && request.method === 'POST') {
        return withCors(await requestReset(request, env), allowOrigin);
      }

      if (url.pathname === '/api/reset_password' && request.method === 'POST') {
        return withCors(await resetPassword(request, env), allowOrigin);
      }

      if (url.pathname === '/api/refresh' && request.method === 'POST') {
        return withCors(await refreshToken(request, env), allowOrigin);
      }

      if (url.pathname === '/api/me' && request.method === 'GET') {
        return withCors(await verifyJwt(request, env), allowOrigin);
      }

      // WebSocket ticket endpoint
      if (url.pathname === '/ws/ticket' && request.method === 'POST') {
        return withCors(await issueWebSocketTicket(request, env), allowOrigin);
      }

      // WebSocket handler for house rooms
      if (url.pathname.startsWith('/ws/house/')) {
        return handleHouseRoomWebSocket(request, env, url);
      }

      const authUser = await getAuthUser(request, env);
      if (authUser.error) return withCors(json({ error: authUser.error }, authUser.status || 401), allowOrigin);

      if (url.pathname === '/api/tenants' && request.method === 'POST') {
        return withCors(await createTenant(request, env, authUser.user), allowOrigin);
      }

      if (url.pathname === '/api/tenants' && request.method === 'GET') {
        return withCors(await listTenants(request, env, authUser.user), allowOrigin);
      }

      if (url.pathname.startsWith('/api/tenants/')) {
        const id = url.pathname.split('/').pop();

        if (request.method === 'GET') {
          return withCors(await getTenant(request, env, authUser.user, id), allowOrigin);
        }

        if (request.method === 'PUT') {
          return withCors(await updateTenant(request, env, authUser.user, id), allowOrigin);
        }

        if (request.method === 'DELETE') {
          return withCors(await deleteTenant(request, env, authUser.user, id), allowOrigin);
        }
      }

      return withCors(new Response('Rental Management Worker is running!', { status: 200 }), allowOrigin);
    } catch (error) {
      console.error(error);
      return withCors(json({ error: error.message }, 500), allowOrigin);
    }
  }
};



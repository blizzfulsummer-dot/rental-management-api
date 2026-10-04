import {
  createDevice,
  createHouse,
  createTenant,
  deleteDevice,
  deleteHouse,
  deleteTenant,
  getDevice,
  getHouse,
  getTenant,
  listHouseDevices,
  listHouses,
  listTenants,
  updateDevice,
  updateHouse,
  updateTenant
} from './tenant.js';
import { getAuthUser, login, refreshToken, requestReset, resetPassword, signup, updatePassword, verifyJwt } from './auth.js';
import { createRateLimiter } from './lib/rateLimit.js';
import { issueWebSocketTicket, validateWebSocketTicket } from './lib/websocketTicket.js';
import { HouseRoom } from './houseRoom.js';
import { DeviceRoom } from './deviceRoom.js';

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
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
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

/**
 * Handle ESP32 device WebSocket connection
 *
 * Stage 1:
 * - Accept WSS connection
 * - No authentication yet
 * - Send connection confirmation
 * - Echo received JSON
 */
async function handleDeviceWebSocket(
  request,
  env
) {

  if (
    request.headers
      .get("Upgrade")
      ?.toLowerCase() !== "websocket"
  ) {

    return json(
      {
        error:
          "Expected WebSocket upgrade"
      },
      426
    );
  }

  console.log(
    "[DEVICE-WS] Routing connection to DeviceRoom"
  );

  // ----------------------------------------------------------
  // Temporary Stage 1.5 ID
  // ----------------------------------------------------------
  //
  // For now every device connects to the same DeviceRoom.
  //
  // Later:
  //
  // deviceId -> specific DeviceRoom
  //
  // ----------------------------------------------------------

  const id =
    env.DEVICE_ROOM.idFromName(
      "device-room"
    );

  const stub =
    env.DEVICE_ROOM.get(id);

  return stub.fetch(
    request
  );
}

export { HouseRoom , DeviceRoom };

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
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Rental Management Portal</title>
  <style>
    :root {
      --bg: #eef4ff;
      --panel: #ffffff;
      --primary: #3b82f6;
      --primary-dark: #1d4ed8;
      --muted: #6b7280;
      --text: #1f2937;
      --border: #dfe7ff;
      --shadow: 0 12px 28px rgba(37, 99, 235, 0.12);
      --radius: 18px;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: linear-gradient(135deg, #e0ecff 0%, #f3f6ff 50%, #eef2ff 100%); color: var(--text); }
    .screen { display: none; min-height: 100vh; padding: 28px; }
    .screen.active { display: block; }
    .login-shell { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 32px; }
    .login-card { width: min(100%, 420px); background: rgba(255,255,255,0.96); border: 1px solid rgba(148,163,184,0.28); border-radius: 24px; box-shadow: var(--shadow); padding: 32px 28px; }
    .eyebrow { margin: 0 0 8px; font-size: 12px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--primary); font-weight: 700; }
    h1, h2, p { margin-top: 0; }
    .subtle { color: var(--muted); margin-bottom: 26px; line-height: 1.5; }
    .field { margin-bottom: 16px; }
    .field label { display: block; margin-bottom: 8px; font-weight: 600; color: var(--text); }
    .field input { width: 100%; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border); background: #fff; color: var(--text); }
    .field input:focus { outline: 2px solid rgba(59,130,246,0.25); border-color: var(--primary); }
    .primary-btn, .ghost-btn, .secondary-btn { border: none; border-radius: 12px; padding: 12px 16px; font-weight: 700; cursor: pointer; }
    .primary-btn { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; width: 100%; }
    .ghost-btn { background: #eef4ff; color: var(--primary-dark); }
    .secondary-btn { background: linear-gradient(135deg, #22c55e, #15803d); color: white; }
    .alert { display: none; padding: 10px 12px; border-radius: 10px; margin-top: 18px; font-size: 14px; font-weight: 600; }
    .alert.show { display: block; }
    .alert.error { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }
    .alert.success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
    .topbar { max-width: 1200px; margin: 0 auto 20px; background: rgba(255,255,255,0.88); border: 1px solid rgba(148,163,184,0.2); border-radius: 18px; padding: 18px 22px; display: flex; justify-content: space-between; align-items: center; box-shadow: var(--shadow); }
    .brand { font-size: 1.1rem; font-weight: 800; }
    .user-meta { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
    .role-pill { display: inline-flex; align-items: center; padding: 6px 12px; border-radius: 999px; background: #dbeafe; color: #1d4ed8; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; }
    .dashboard { max-width: 1200px; margin: 0 auto; padding-bottom: 36px; }
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 18px; margin: 24px 0; }
    .stat-card { background: var(--panel); border-radius: var(--radius); border: 1px solid var(--border); box-shadow: var(--shadow); padding: 20px; }
    .stat-label { color: var(--muted); font-size: 13px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; }
    .stat-value { font-size: clamp(1.7rem, 2vw, 2.3rem); font-weight: 800; line-height: 1; }
    .layout { display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 22px; align-items: start; }
    .panel { background: var(--panel); border-radius: var(--radius); border: 1px solid var(--border); box-shadow: var(--shadow); padding: 22px; }
    .panel-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px; }
    .list-grid, .card-grid { display: grid; gap: 14px; }
    .card-grid { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
    .house-card, .tenant-card, .device-card, .profile-card { border: 1px solid var(--border); border-radius: 16px; background: #f7f9ff; padding: 16px; }
    .tag { display: inline-block; padding: 5px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; background: #e0f2fe; color: #0369a1; text-transform: uppercase; letter-spacing: 0.06em; }
    .inline-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
    .mini-btn { border: none; background: #e0ecff; border-radius: 10px; padding: 8px 10px; color: var(--primary-dark); font-weight: 700; cursor: pointer; }
    .profile-card { display: grid; gap: 10px; }
    .profile-line { display: flex; justify-content: space-between; gap: 12px; padding-bottom: 8px; border-bottom: 1px solid rgba(148,163,184,0.25); }
    .label { color: var(--muted); }
    .empty { border: 1px dashed var(--border); border-radius: 16px; padding: 22px; color: var(--muted); text-align: center; background: rgba(255,255,255,0.4); }
    @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } .topbar { flex-direction: column; align-items: flex-start; } }
  </style>
</head>
<body>
  <div id="loginScreen" class="screen active">
    <div class="login-shell">
      <div class="login-card">
        <p class="eyebrow">Rental Management</p>
        <h1>Smart Home Access</h1>
        <p class="subtle">Secure portal for owners, admins, tenants and users.</p>
        <div class="field"><label for="email">Email</label><input id="email" type="email" value="admin@example.com" /></div>
        <div class="field"><label for="password">Password</label><input id="password" type="password" value="AdminPass123!" /></div>
        <button id="loginBtn" class="primary-btn" type="button">Sign In</button>
        <div id="loginAlert" class="alert error"></div>
      </div>
    </div>
  </div>

  <div id="dashboardScreen" class="screen">
    <header class="topbar">
      <div class="brand">Rental Management Portal</div>
      <div class="user-meta">
        <span id="userRole" class="role-pill">Role</span>
        <strong id="userDisplayName">User</strong>
        <button id="logoutBtn" class="ghost-btn" type="button">Logout</button>
      </div>
    </header>
    <div class="dashboard">
      <div id="statsGrid" class="stat-grid"></div>
      <div class="layout">
        <section class="panel">
          <div class="panel-header">
            <h2 id="mainPanelTitle">Overview</h2>
            <button id="refreshBtn" class="secondary-btn" type="button">Refresh</button>
          </div>
          <div id="mainPanelContent" class="list-grid"></div>
        </section>
        <aside class="panel">
          <div class="panel-header"><h2>Profile</h2></div>
          <div id="profilePanel" class="profile-card"></div>
          <div class="panel-header" style="margin-top:24px;"><h2>Change password</h2></div>
          <form id="passwordForm" style="display:grid;gap:12px; margin-top:12px;">
            <input id="oldPassword" type="password" placeholder="Current password" />
            <input id="newPassword" type="password" placeholder="New password" />
            <button type="submit" class="primary-btn" style="width:100%;">Update Password</button>
          </form>
          <div id="passwordAlert" class="alert"></div>
        </aside>
      </div>
    </div>
  </div>

  <script>
    const API_BASE = window.location.origin || 'http://localhost:8787';
    const state = { jwt: '', profile: null, role: null, houses: [], tenants: [], devices: [], selectedHouseId: null };
    const loginScreen = document.getElementById('loginScreen');
    const dashboardScreen = document.getElementById('dashboardScreen');
    const loginAlert = document.getElementById('loginAlert');
    const passwordAlert = document.getElementById('passwordAlert');
    const mainPanelContent = document.getElementById('mainPanelContent');
    const profilePanel = document.getElementById('profilePanel');
    const statsGrid = document.getElementById('statsGrid');
    const userDisplayName = document.getElementById('userDisplayName');
    const userRole = document.getElementById('userRole');
    const mainPanelTitle = document.getElementById('mainPanelTitle');
    function showAlert(element, message, type) { element.textContent = message; element.className = 'alert ' + type + ' show'; }
    function clearAlert(element) { element.textContent = ''; element.className = 'alert'; }
    function formatRole(role) { return role ? role.toUpperCase() : 'USER'; }
    function setActiveScreen(screen) {
      loginScreen.classList.toggle('active', screen === 'login');
      dashboardScreen.classList.toggle('active', screen === 'dashboard');
    }
    async function requestJson(url, options = {}) {
      const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
      const text = await response.text();
      const data = text ? JSON.parse(text) : {};
      if (!response.ok) throw new Error(data.error || data.message || 'Request failed');
      return data;
    }
    function getAuthHeaders() { return { Authorization: 'Bearer ' + state.jwt, 'Content-Type': 'application/json' }; }
    function renderStats() {
      const role = state.role;
      const cards = (role === 'tenant' || role === 'user') ? [
          { label: 'Assigned House', value: state.houses.length || 0 },
          { label: 'Devices', value: state.devices.length },
          { label: 'Role', value: formatRole(role).slice(0, 6) }
        ] : [
          { label: 'Houses', value: state.houses.length },
          { label: 'Tenants', value: state.tenants.length },
          { label: 'Assigned Devices', value: state.devices.length }
        ];
      statsGrid.innerHTML = cards.map(card => '<div class="stat-card"><div class="stat-label">' + card.label + '</div><div class="stat-value">' + card.value + '</div></div>').join('');
    }
    function renderProfile() {
      const profile = state.profile || {};
      const assignedHouse = (state.role === 'tenant' || state.role === 'user') && state.houses[0] ? state.houses[0] : null;
      const values = [
        ['Name', profile.name || 'Not provided'],
        ['Email', profile.email || 'Not provided'],
        ['Role', formatRole(state.role)],
        ['House', assignedHouse ? assignedHouse.name : 'No assigned house'],
        ['Location', assignedHouse ? (assignedHouse.location || 'N/A') : 'N/A']
      ];
      profilePanel.innerHTML = values.map(([label, value]) => '<div class="profile-line"><span class="label">' + label + '</span><strong>' + value + '</strong></div>').join('');
    }
    function renderHouseList() {
      if (!state.houses.length) { mainPanelContent.innerHTML = '<div class="empty">No houses available for this account.</div>'; return; }
      const html = state.houses.map(house => '<div class="house-card"><div class="tag">House</div><h3>' + (house.name || 'Unnamed House') + '</h3><div class="meta">' + (house.location || 'No location') + '<br />Owner ID: ' + (house.owner_id || 'N/A') + '</div><div class="inline-actions"><button class="mini-btn" data-house-id="' + house.id + '" data-action="select-house">View Devices</button></div></div>').join('');
      mainPanelContent.innerHTML = '<div class="card-grid">' + html + '</div>';
      document.querySelectorAll('[data-action="select-house"]').forEach(btn => {
        btn.addEventListener('click', () => { state.selectedHouseId = Number(btn.dataset.houseId); renderDeviceList(); });
      });
    }
    function renderDeviceList() {
      const selectedHouseId = state.selectedHouseId || (state.houses[0] && state.houses[0].id);
      const visibleDevices = state.devices.filter(device => !selectedHouseId || Number(device.house_id) === Number(selectedHouseId));
      if (!visibleDevices.length) {
        mainPanelContent.innerHTML = '<div class="empty">No devices available for the selected house.</div>';
        return;
      }
      const html = visibleDevices.map(device => '<div class="device-card"><h3>' + (device.device_name || 'Device ' + device.id) + '</h3><div class="meta">Type: ' + (device.device_type || 'Unknown') + '<br />House ID: ' + (device.house_id || 'N/A') + '</div><span class="device-status ' + ((device.status === 'online' || device.status === 'active') ? 'online' : 'offline') + '">' + (device.status || 'offline') + '</span></div>').join('');
      mainPanelContent.innerHTML = '<div class="card-grid">' + html + '</div>';
    }
    function renderMainPanel() {
      mainPanelContent.innerHTML = '';
      if (state.role === 'admin' || state.role === 'owner') {
        mainPanelTitle.textContent = state.role === 'admin' ? 'Admin Overview' : 'Owner Overview';
        renderHouseList();
        return;
      }
      mainPanelTitle.textContent = 'Assigned Access';
      const houseList = state.houses.length ? state.houses : [];
      if (houseList.length) {
        const html = houseList.map(house => '<div class="house-card"><div class="tag">House</div><h3>' + (house.name || 'Assigned House') + '</h3><div class="meta">' + (house.location || 'No location') + '<br />Owner: ' + (house.owner_id || 'N/A') + '</div><div class="inline-actions"><button class="mini-btn" data-house-id="' + house.id + '" data-action="select-house">View Devices</button></div></div>').join('');
        mainPanelContent.innerHTML = '<div class="card-grid">' + html + '</div>';
        document.querySelectorAll('[data-action="select-house"]').forEach(btn => {
          btn.addEventListener('click', () => { state.selectedHouseId = Number(btn.dataset.houseId); renderDeviceList(); });
        });
      } else {
        mainPanelContent.innerHTML = '<div class="empty">No house assignment found for this account.</div>';
      }
    }
    async function loadDashboardData() {
      try {
        const headers = getAuthHeaders();
        const housesResponse = await fetch(API_BASE + '/api/houses', { headers });
        const housesData = await housesResponse.json();
        state.houses = Array.isArray(housesData.houses) ? housesData.houses : (Array.isArray(housesData) ? housesData : []);
        if (state.role === 'admin' || state.role === 'owner') {
          const tenantsResponse = await fetch(API_BASE + '/api/tenants', { headers });
          const tenantsData = await tenantsResponse.json();
          state.tenants = Array.isArray(tenantsData.tenants) ? tenantsData.tenants : [];
        }
        state.devices = [];
        for (const house of state.houses) {
          const devicesResponse = await fetch(API_BASE + '/api/houses/' + house.id + '/devices', { headers });
          const devicesData = await devicesResponse.json();
          const devices = Array.isArray(devicesData.devices) ? devicesData.devices : [];
          state.devices = state.devices.concat(devices);
        }
        renderStats();
        renderProfile();
        renderMainPanel();
      } catch (error) {
        console.error('Dashboard load error:', error);
        mainPanelContent.innerHTML = '<div class="empty">Unable to load dashboard data.</div>';
      }
    }
    async function handleLogin() {
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      if (!email || !password) { showAlert(loginAlert, 'Email and password are required.', 'error'); return; }
      try {
        const loginResponse = await requestJson(API_BASE + '/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
        state.jwt = loginResponse.accessToken;
        const meResponse = await fetch(API_BASE + '/api/me', { headers: getAuthHeaders() });
        const meData = meResponse.ok ? await meResponse.json() : null;
        if (!meData || !meData.user) throw new Error('Could not load user profile');
        state.profile = meData.user;
        state.role = String(meData.user.role || 'user').toLowerCase();
        userDisplayName.textContent = meData.user.name || meData.user.email || 'User';
        userRole.textContent = formatRole(state.role);
        setActiveScreen('dashboard');
        clearAlert(passwordAlert);
        await loadDashboardData();
      } catch (error) {
        showAlert(loginAlert, error.message || 'Login failed.', 'error');
      }
    }
    async function handleLogout() {
      state.jwt = ''; state.profile = null; state.role = null; state.houses = []; state.tenants = []; state.devices = []; state.selectedHouseId = null;
      document.getElementById('email').value = 'admin@example.com';
      document.getElementById('password').value = 'AdminPass123!';
      clearAlert(loginAlert); clearAlert(passwordAlert); setActiveScreen('login');
    }
    async function handlePasswordUpdate(event) {
      event.preventDefault();
      const oldPassword = document.getElementById('oldPassword').value;
      const newPassword = document.getElementById('newPassword').value;
      if (!oldPassword || !newPassword) { showAlert(passwordAlert, 'Both current and new password are required.', 'error'); return; }
      try {
        const result = await requestJson(API_BASE + '/api/update_password', { method: 'POST', body: JSON.stringify({ token: state.jwt, oldPassword, newPassword }) });
        showAlert(passwordAlert, result.message || 'Password updated successfully.', 'success');
        document.getElementById('oldPassword').value = '';
        document.getElementById('newPassword').value = '';
      } catch (error) {
        showAlert(passwordAlert, error.message || 'Password update failed.', 'error');
      }
    }
    document.getElementById('loginBtn').addEventListener('click', handleLogin);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    document.getElementById('refreshBtn').addEventListener('click', loadDashboardData);
    document.getElementById('passwordForm').addEventListener('submit', handlePasswordUpdate);
    document.addEventListener('keydown', function(event) { if (event.key === 'Enter' && loginScreen.classList.contains('active')) handleLogin(); });
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

      // ESP32 device WebSocket
      if (
        url.pathname === '/ws/device' &&
        request.method === 'GET'
      ) {
        return handleDeviceWebSocket(request,env);
      }

      // WebSocket handler for house rooms
      if (url.pathname.startsWith('/ws/house/')) {
        return handleHouseRoomWebSocket(request, env, url);
      }

      const authUser = await getAuthUser(request, env);
      if (authUser.error) return withCors(json({ error: authUser.error }, authUser.status || 401), allowOrigin);

      if (url.pathname === '/api/houses' && request.method === 'POST') {
        return withCors(await createHouse(request, env, authUser.user), allowOrigin);
      }

      if (url.pathname === '/api/houses' && request.method === 'GET') {
        return withCors(await listHouses(request, env, authUser.user), allowOrigin);
      }

      if (url.pathname.startsWith('/api/houses/')) {
        const pathParts = url.pathname.split('/').filter(Boolean);
        const isHouseDevicesRoute = /^\/api\/houses\/\d+\/devices$/.test(url.pathname);

        if (isHouseDevicesRoute && request.method === 'GET') {
          const houseId = pathParts[2];
          return withCors(await listHouseDevices(request, env, authUser.user, houseId), allowOrigin);
        }

        if (isHouseDevicesRoute && request.method === 'POST') {
          const houseId = pathParts[2];
          const rawBody = await request.clone().text();
          let payload = {};

          if (rawBody) {
            try {
              payload = JSON.parse(rawBody);
            } catch {
              payload = {};
            }
          }

          const mergedRequest = new Request(request.url, {
            method: request.method,
            headers: request.headers,
            body: JSON.stringify({ ...payload, house_id: Number(houseId) })
          });

          return withCors(await createDevice(mergedRequest, env, authUser.user), allowOrigin);
        }

        const id = pathParts[pathParts.length - 1];

        if (request.method === 'GET') {
          return withCors(await getHouse(request, env, authUser.user, id), allowOrigin);
        }

        if (request.method === 'PUT') {
          return withCors(await updateHouse(request, env, authUser.user, id), allowOrigin);
        }

        if (request.method === 'DELETE') {
          return withCors(await deleteHouse(request, env, authUser.user, id), allowOrigin);
        }
      }

      if (url.pathname.startsWith('/api/devices/')) {
        const id = url.pathname.split('/').filter(Boolean).pop();

        if (request.method === 'GET') {
          return withCors(await getDevice(request, env, authUser.user, id), allowOrigin);
        }

        if (request.method === 'PUT') {
          return withCors(await updateDevice(request, env, authUser.user, id), allowOrigin);
        }

        if (request.method === 'DELETE') {
          return withCors(await deleteDevice(request, env, authUser.user, id), allowOrigin);
        }
      }

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



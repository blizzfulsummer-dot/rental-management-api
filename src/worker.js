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
  rotateDevicePairingKey,
  updateDevice,
  updateHouse,
  updateTenant
} from './tenant.js';
import { getAuthUser, login, refreshToken, requestReset, resetPassword, signup, updatePassword, verifyJwt } from './auth.js';
import { createRateLimiter } from './lib/rateLimit.js';
import { issueDeviceWebSocketTicket, issueWebSocketTicket, validateWebSocketTicket } from './lib/websocketTicket.js';
import { HouseRoom } from './houseRoom.js';
import { DeviceRoom } from './deviceRoom.js';
import {
  cancelFingerprintEnrollment,
  listFingerprintEnrollments,
  removeFingerprintEnrollment,
  startFingerprintEnrollment
} from './fingerprints.js';

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
  sessionUrl.searchParams.set('houseId', validation.houseId);
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
    .field label { display: block; margin-bottom: 8px; font-weight: 600; }
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
    .view-tabs { display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0 18px; }
    .view-tab { border: 1px solid var(--border); background: #f8faff; color: var(--text); border-radius: 999px; padding: 9px 14px; font-weight: 700; cursor: pointer; }
    .view-tab.active { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; border-color: transparent; }
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
    .house-selector { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; color: var(--muted); font-weight: 700; }
    .house-selector select { min-width: min(100%, 260px); padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; background: white; color: var(--text); font: inherit; }
    .device-edit-form { display: grid; gap: 10px; margin: 14px 0; }
    .device-edit-form input { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; background: #fff; color: var(--text); }
    .pairing-key-panel { margin: 14px 0; padding: 14px; border: 1px solid var(--border); border-radius: 12px; background: #eff6ff; }
    .pairing-key-panel code { display: block; margin: 10px 0; padding: 10px; overflow-wrap: anywhere; background: white; border-radius: 8px; }
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
      <div id="viewTabs" class="view-tabs" aria-label="Main navigation"></div>
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
    function resolveApiBase() {
      const host = window.location.hostname;
      const origin = window.location.origin;

      if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || origin.includes('8787')) {
        return origin || 'http://127.0.0.1:8787';
      }

      if (host === 'rental-management.ehexibit.com') {
        return 'https://api.ehexibit.com';
      }

      return origin || 'http://127.0.0.1:8787';
    }

    const API_BASE = resolveApiBase();
    const state = { jwt: '', profile: null, role: null, houses: [], tenants: [], devices: [], fingerprints: {}, selectedHouseId: null, activeView: 'overview' };
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
    const viewTabs = document.getElementById('viewTabs');

    function showAlert(element, message, type) { element.textContent = message; element.className = 'alert ' + type + ' show'; }
    function clearAlert(element) { element.textContent = ''; element.className = 'alert'; }
    function escapeHtml(value) { return String(value).replace(/[&<>"']/g, function(character) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]; }); }
    function formatRole(role) { return role ? role.toUpperCase() : 'USER'; }
    function getRoleViews() {
      if (state.role === 'admin' || state.role === 'owner') {
        return ['overview', 'houses', 'tenants', 'devices'];
      }
      return ['overview', 'houses', 'devices'];
    }
    function renderViewTabs() {
      const views = getRoleViews();
      const labels = { overview: 'Overview', houses: 'Houses', tenants: 'Tenants', devices: 'Devices' };
      viewTabs.innerHTML = views.map(function(view) {
        return '<button type="button" class="view-tab ' + (state.activeView === view ? 'active' : '') + '" data-view="' + view + '">' + labels[view] + '</button>';
      }).join('');
      viewTabs.querySelectorAll('[data-view]').forEach(function(button) {
        button.addEventListener('click', function() {
          state.activeView = button.dataset.view;
          renderViewTabs();
          renderMainPanel();
        });
      });
    }
    function setActiveScreen(screen) { loginScreen.classList.toggle('active', screen === 'login'); dashboardScreen.classList.toggle('active', screen === 'dashboard'); }
    async function requestJson(url, options) {
      options = options || {};
      const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
      const text = await response.text();
      const data = text ? JSON.parse(text) : {};
      if (!response.ok) throw new Error(data.error || data.message || 'Request failed');
      return data;
    }
    function getAuthHeaders() { return { Authorization: 'Bearer ' + state.jwt, 'Content-Type': 'application/json' }; }
    function renderStats() {
      const role = state.role;
      const cards = (role === 'tenant' || role === 'user')
        ? [
            { label: 'Assigned House', value: state.houses.length || 0 },
            { label: 'Devices', value: state.devices.length },
            { label: 'Role', value: formatRole(role).slice(0, 6) }
          ]
        : [
            { label: 'Houses', value: state.houses.length },
            { label: 'Tenants', value: state.tenants.length },
            { label: 'Assigned Devices', value: state.devices.length }
          ];
      statsGrid.innerHTML = cards.map(function(card) { return '<div class="stat-card"><div class="stat-label">' + card.label + '</div><div class="stat-value">' + card.value + '</div></div>'; }).join('');
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
      profilePanel.innerHTML = values.map(function(pair) { return '<div class="profile-line"><span class="label">' + pair[0] + '</span><strong>' + pair[1] + '</strong></div>'; }).join('');
    }
    function renderHouseList() {
      if (!state.houses.length) {
        mainPanelContent.innerHTML = '<div class="empty">No houses available for this account.</div>';
        return;
      }
      const html = state.houses.map(function(house) {
        return '<div class="house-card"><div class="tag">House</div><h3>' + (house.name || 'Unnamed House') + '</h3><div class="meta">' + (house.location || 'No location') + '<br />Owner ID: ' + (house.owner_id || 'N/A') + '</div><div class="inline-actions"><button class="mini-btn" data-house-id="' + house.id + '" data-action="select-house">View Devices</button></div></div>';
      }).join('');
      mainPanelContent.innerHTML = '<div class="card-grid">' + html + '</div>';
      document.querySelectorAll('[data-action="select-house"]').forEach(function(btn) {
        btn.addEventListener('click', function() {
          state.selectedHouseId = Number(btn.dataset.houseId);
          state.activeView = 'devices';
          renderViewTabs();
          renderMainPanel();
        });
      });
    }
    function renderTenantList() {
      if (!state.tenants.length) {
        mainPanelContent.innerHTML = '<div class="empty">No tenants assigned to this account scope.</div>';
        return;
      }
      const html = state.tenants.map(function(tenant) {
        return '<div class="tenant-card"><h3>' + (tenant.name || tenant.email || 'Tenant') + '</h3><div class="meta">' + (tenant.email || 'No email') + '<br />Unit: ' + (tenant.leased_unit || 'N/A') + '<br />Rent: ' + (tenant.rent_amount || 'N/A') + '</div><div class="tag">Tenant</div></div>';
      }).join('');
      mainPanelContent.innerHTML = '<div class="card-grid">' + html + '</div>';
    }
    function renderDeviceList() {
      if (!state.houses.length) {
        mainPanelContent.innerHTML = '<div class="empty">No house is assigned to this account, so there are no house devices to show.</div>';
        return;
      }
      const selectedHouse = state.houses.find(function(house) { return Number(house.id) === Number(state.selectedHouseId); }) || state.houses[0];
      state.selectedHouseId = Number(selectedHouse.id);
      const selectedHouseId = selectedHouse.id;
      const visibleDevices = state.devices.filter(function(device) {
        return Number(device.house_id) === Number(selectedHouseId);
      });
      const html = visibleDevices.map(function(device) {
        const online = ['online', 'active', 'on'].includes(String(device.status || '').toLowerCase());
        const management = state.role === 'admin' || state.role === 'owner';
        const enrollments = state.fingerprints[device.id] || [];
        const mine = enrollments.find(function(item) { return Number(item.user_id) === Number(state.profile && state.profile.id); });
        const fingerprintRows = management ? enrollments.map(function(item) {
          return '<div class="inline-actions"><span class="meta">Slot ' + item.fingerprint_id + ': ' + escapeHtml(item.name || item.email || ('User ' + item.user_id)) + ': ' + escapeHtml(item.status) + (item.enrollment_pending ? ' (enrollment in progress)' : '') + '</span>' +
            (item.status !== 'disabled' ? '<button class="mini-btn" type="button" data-fingerprint-action="disable" data-device-id="' + device.id + '" data-fingerprint-id="' + item.fingerprint_id + '">Disable</button><button class="mini-btn" type="button" data-fingerprint-action="delete" data-device-id="' + device.id + '" data-fingerprint-id="' + item.fingerprint_id + '">Delete</button>' : '') + '</div>';
        }).join('') : '';
        const controls = '<div class="inline-actions"><button class="mini-btn" type="button" data-device-command="door.unlock" data-device-id="' + device.id + '">Unlock door (5 sec)</button><button class="mini-btn" type="button" data-device-command="door.lock" data-device-id="' + device.id + '">Lock door</button><button class="mini-btn" type="button" data-device-command="io.set" data-control-id="relay2" data-control-state="true" data-device-id="' + device.id + '">Relay 2 on</button><button class="mini-btn" type="button" data-device-command="io.set" data-control-id="relay2" data-control-state="false" data-device-id="' + device.id + '">Relay 2 off</button></div>' +
          '<div class="device-edit-form"><strong>Fingerprint access</strong><p class="meta">' + (mine ? 'Your fingerprint: slot ' + mine.fingerprint_id + ' (' + escapeHtml(mine.status) + (mine.enrollment_pending ? ', enrollment in progress' : '') + ')' : 'No fingerprint is registered for your account on this device.') + '</p><div class="inline-actions"><button class="mini-btn" type="button" data-fingerprint-enroll data-device-id="' + device.id + '">' + (mine && mine.status === 'active' ? 'Re-enroll my fingerprint' : 'Register my fingerprint') + '</button></div>' + fingerprintRows + '<div class="meta" data-fingerprint-status="' + device.id + '" aria-live="polite"></div></div>' +
          (management
            ? '<form class="device-edit-form" data-device-id="' + device.id + '"><input name="name" aria-label="Device name" value="' + escapeHtml(device.device_name || '') + '" required /><input name="type" aria-label="Device type" value="' + escapeHtml(device.device_type || '') + '" required /><div class="inline-actions"><button class="mini-btn" type="submit">Save</button><button class="mini-btn" type="button" data-delete-device="' + device.id + '">Delete</button></div></form><div class="inline-actions"><span class="tag">' + (device.pairing_configured ? 'ESP32 paired' : 'ESP32 not paired') + '</span><button class="mini-btn" type="button" data-pair-device="' + device.id + '">' + (device.pairing_configured ? 'Regenerate pairing key' : 'Pair ESP32') + '</button></div>'
            : '');
        return '<div class="device-card"><h3>' + escapeHtml(device.device_name || 'Device ' + device.id) + '</h3><div class="meta">Type: ' + escapeHtml(device.device_type || 'Unknown') + '<br />House: ' + escapeHtml(selectedHouse.name || 'House ' + selectedHouse.id) + '</div><span class="device-status ' + (online ? 'online' : 'offline') + '">' + escapeHtml(device.status || 'offline') + '</span>' + controls + '</div>';
      }).join('');
      const options = state.houses.map(function(house) {
        return '<option value="' + house.id + '"' + (Number(house.id) === Number(selectedHouseId) ? ' selected' : '') + '>' + escapeHtml(house.name || 'House ' + house.id) + '</option>';
      }).join('');
      const content = visibleDevices.length ? '<div class="card-grid">' + html + '</div>' : '<div class="empty">No devices are associated with this house yet.</div>';
      const addForm = state.role === 'admin' || state.role === 'owner'
        ? '<form id="addDeviceForm" class="device-edit-form"><strong>Add a device to ' + escapeHtml(selectedHouse.name || 'House ' + selectedHouse.id) + '</strong><input name="name" aria-label="New device name" placeholder="Device name" required /><input name="type" aria-label="New device type" placeholder="Device type (e.g. Switch)" required /><button class="primary-btn" type="submit">Add device</button></form>'
        : '';
      mainPanelContent.innerHTML = '<label class="house-selector" for="deviceHouseSelect">Devices for house <select id="deviceHouseSelect">' + options + '</select></label><div id="deviceNotice" class="alert"></div>' + addForm + content;
      document.getElementById('deviceHouseSelect').addEventListener('change', function(event) {
        state.selectedHouseId = Number(event.target.value);
        renderMainPanel();
      });
      const deviceNotice = document.getElementById('deviceNotice');
      function showPairingKey(deviceId, pairingKey) {
        const notice = document.getElementById('deviceNotice');
        if (!notice) return;
        const apiUrl = new URL(API_BASE);
        const panel = document.createElement('div');
        panel.className = 'pairing-key-panel';
        const heading = document.createElement('strong');
        heading.textContent = 'One-time ESP32 pairing key';
        const instructions = document.createElement('p');
        instructions.textContent = 'Save this key now. Configure API host ' + apiUrl.hostname + ', port ' + (apiUrl.port || (apiUrl.protocol === 'https:' ? '443' : '80')) + ', secure ' + (apiUrl.protocol === 'https:' ? 'true' : 'false') + ', device ID ' + deviceId + ', enable authentication, and paste the key as the device credential. The key will not be shown again.';
        const key = document.createElement('code');
        key.textContent = pairingKey;
        const copy = document.createElement('button');
        copy.className = 'mini-btn';
        copy.type = 'button';
        copy.textContent = 'Copy pairing key';
        copy.addEventListener('click', async function() {
          try {
            await navigator.clipboard.writeText(pairingKey);
            copy.textContent = 'Copied';
          } catch (error) {
            console.error('Could not copy device pairing key:', error);
            copy.textContent = 'Select and copy the key above';
          }
        });
        panel.append(heading, instructions, key, copy);
        notice.replaceChildren(panel);
        notice.className = 'alert success show';
      }
      async function refreshDevices() {
        state.devices = [];
        await loadDashboardData();
        state.activeView = 'devices';
        renderMainPanel();
      }
      async function openDeviceSocket(deviceId) {
        const ticketData = await requestJson(API_BASE + '/ws/ticket', {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify({ houseId: Number(selectedHouseId), deviceId: Number(deviceId), clientType: 'web' })
        });
        const socket = new WebSocket(API_BASE.replace(/^http/, 'ws') + '/ws/house/' + selectedHouseId + '?ticket=' + encodeURIComponent(ticketData.ticket));
        await new Promise(function(resolve, reject) {
          const timeout = window.setTimeout(function() {
            socket.close();
            reject(new Error('Could not connect to the device control channel.'));
          }, 10000);
          socket.addEventListener('open', function() { window.clearTimeout(timeout); resolve(); }, { once: true });
          socket.addEventListener('error', function() { window.clearTimeout(timeout); reject(new Error('Could not connect to the device control channel.')); }, { once: true });
        });
        return socket;
      }
      document.querySelectorAll('[data-fingerprint-enroll]').forEach(function(button) {
        button.addEventListener('click', async function() {
          const deviceId = Number(button.dataset.deviceId);
          const current = (state.fingerprints[deviceId] || []).find(function(item) { return Number(item.user_id) === Number(state.profile && state.profile.id); });
          if (current && current.status === 'active' && !window.confirm('Re-enroll and replace your current fingerprint on this device?')) return;
          button.disabled = true;
          let socket;
          let reserved = false;
          const status = document.querySelector('[data-fingerprint-status="' + deviceId + '"]');
          try {
            const reservation = await requestJson(API_BASE + '/api/devices/' + deviceId + '/fingerprints/enroll', {
              method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({})
            });
            reserved = true;
            socket = await openDeviceSocket(deviceId);
            socket.send(JSON.stringify({ type: 'device_command', targetDeviceId: deviceId, command: 'fingerprint.register', id: reservation.fingerprintId }));
            if (status) status.textContent = 'Place your finger on the sensor, then remove and scan it again.';
            await new Promise(function(resolve, reject) {
              let acknowledged = false;
              const timeout = window.setTimeout(function() { reject(new Error('Fingerprint enrollment timed out.')); }, 70000);
              socket.addEventListener('message', function(event) {
                let message;
                try { message = JSON.parse(event.data); } catch { return; }
                if (message.type === 'device_response' && Number(message.deviceId) === deviceId && message.command === 'fingerprint.register') {
                  if (message.success === false) {
                    window.clearTimeout(timeout);
                    reject(new Error(message.message || 'The device rejected fingerprint enrollment.'));
                  } else acknowledged = true;
                } else if (message.type === 'fingerprint.event' && Number(message.deviceId) === deviceId &&
                           Number(message.id) === Number(reservation.fingerprintId) &&
                           (message.event === 'enrollment_complete' || message.event === 'enrollment_failed')) {
                  window.clearTimeout(timeout);
                  if (message.event === 'enrollment_complete' && message.success === true) resolve();
                  else reject(new Error(message.message || 'Fingerprint enrollment failed.'));
                } else if (message.type === 'error') {
                  window.clearTimeout(timeout);
                  reject(new Error(message.error || 'Fingerprint enrollment failed.'));
                }
              });
              socket.addEventListener('close', function() {
                if (acknowledged) {
                  window.clearTimeout(timeout);
                  reject(new Error('Device disconnected before enrollment completed.'));
                }
              }, { once: true });
            });
            reserved = false;
            await refreshDevices();
            const updatedStatus = document.querySelector('[data-fingerprint-status="' + deviceId + '"]');
            if (updatedStatus) updatedStatus.textContent = 'Fingerprint registered successfully.';
          } catch (error) {
            if (reserved) {
              try {
                await requestJson(API_BASE + '/api/devices/' + deviceId + '/fingerprints/enroll', { method: 'DELETE', headers: getAuthHeaders() });
              } catch (cancelError) {
                console.error('Could not cancel reserved fingerprint enrollment:', cancelError);
              }
            }
            if (status) status.textContent = error.message || 'Fingerprint enrollment failed.';
          } finally {
            if (socket && socket.readyState < WebSocket.CLOSING) socket.close();
            button.disabled = false;
          }
        });
      });
      document.querySelectorAll('[data-fingerprint-action]').forEach(function(button) {
        button.addEventListener('click', async function() {
          const action = button.dataset.fingerprintAction;
          const deviceId = Number(button.dataset.deviceId);
          const fingerprintId = Number(button.dataset.fingerprintId);
          if (!window.confirm((action === 'disable' ? 'Disable' : 'Delete') + ' this fingerprint? Its sensor template will be removed.')) return;
          button.disabled = true;
          let socket;
          try {
            socket = await openDeviceSocket(deviceId);
            socket.send(JSON.stringify({ type: 'device_command', targetDeviceId: deviceId, command: 'fingerprint.delete', id: fingerprintId }));
            await new Promise(function(resolve, reject) {
              const timeout = window.setTimeout(function() { reject(new Error('The device did not confirm fingerprint removal.')); }, 10000);
              socket.addEventListener('message', function(event) {
                let message;
                try { message = JSON.parse(event.data); } catch { return; }
                if (message.type === 'device_response' && Number(message.deviceId) === deviceId && message.command === 'fingerprint.delete') {
                  window.clearTimeout(timeout);
                  if (message.success === false) reject(new Error(message.message || 'The device rejected fingerprint removal.'));
                  else resolve();
                } else if (message.type === 'error') {
                  window.clearTimeout(timeout);
                  reject(new Error(message.error || 'Fingerprint removal failed.'));
                }
              });
            });
            await requestJson(API_BASE + '/api/devices/' + deviceId + '/fingerprints/' + fingerprintId, {
              method: 'DELETE', headers: getAuthHeaders(), body: JSON.stringify({ action: action })
            });
            await refreshDevices();
          } catch (error) {
            showAlert(document.getElementById('deviceNotice') || deviceNotice, error.message || 'Unable to remove fingerprint.', 'error');
          } finally {
            if (socket && socket.readyState < WebSocket.CLOSING) socket.close();
            button.disabled = false;
          }
        });
      });
      const addDeviceForm = document.getElementById('addDeviceForm');
      if (addDeviceForm) addDeviceForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        try {
          const result = await requestJson(API_BASE + '/api/houses/' + selectedHouseId + '/devices', { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ name: formData.get('name'), type: formData.get('type') }) });
          await refreshDevices();
          showPairingKey(result.device.id, result.pairing_key);
        } catch (error) {
          showAlert(deviceNotice, error.message || 'Unable to add device.', 'error');
        }
      });
      document.querySelectorAll('.device-edit-form[data-device-id]').forEach(function(form) {
        form.addEventListener('submit', async function(event) {
          event.preventDefault();
          const formData = new FormData(event.currentTarget);
          try {
            await requestJson(API_BASE + '/api/devices/' + form.dataset.deviceId, { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify({ name: formData.get('name'), type: formData.get('type') }) });
            await refreshDevices();
          } catch (error) {
            showAlert(deviceNotice, error.message || 'Unable to update device.', 'error');
          }
        });
      });
      document.querySelectorAll('[data-delete-device]').forEach(function(button) {
        button.addEventListener('click', async function() {
          if (!window.confirm('Delete this device?')) return;
          try {
            await requestJson(API_BASE + '/api/devices/' + button.dataset.deleteDevice, { method: 'DELETE', headers: getAuthHeaders() });
            await refreshDevices();
          } catch (error) {
            showAlert(deviceNotice, error.message || 'Unable to delete device.', 'error');
          }
        });
      });
      document.querySelectorAll('[data-pair-device]').forEach(function(button) {
        button.addEventListener('click', async function() {
          if (!window.confirm('Generate a new pairing key? The current key will stop working.')) return;
          try {
            const result = await requestJson(API_BASE + '/api/devices/' + button.dataset.pairDevice + '/pairing-key', { method: 'POST', headers: getAuthHeaders() });
            await refreshDevices();
            showPairingKey(button.dataset.pairDevice, result.pairing_key);
          } catch (error) {
            showAlert(document.getElementById('deviceNotice') || deviceNotice, error.message || 'Unable to pair device.', 'error');
          }
        });
      });
      document.querySelectorAll('[data-device-command]').forEach(function(button) {
        button.addEventListener('click', async function() {
          button.disabled = true;
          let socket;
          try {
            const ticketData = await requestJson(API_BASE + '/ws/ticket', {
              method: 'POST',
              headers: getAuthHeaders(),
              body: JSON.stringify({ houseId: Number(selectedHouseId), deviceId: Number(button.dataset.deviceId), clientType: 'web' })
            });
            socket = new WebSocket(API_BASE.replace(/^http/, 'ws') + '/ws/house/' + selectedHouseId + '?ticket=' + encodeURIComponent(ticketData.ticket));
            await new Promise(function(resolve, reject) {
              let timeout = window.setTimeout(function() {
                socket.close();
                reject(new Error('Device did not acknowledge the command in time.'));
              }, 10000);
              socket.addEventListener('open', function() {
                socket.send(JSON.stringify({
                  type: 'device_command',
                  targetDeviceId: Number(button.dataset.deviceId),
                  command: button.dataset.deviceCommand,
                  id: button.dataset.controlId || '',
                  state: button.dataset.controlState === 'true'
                }));
              }, { once: true });
              socket.addEventListener('message', function(event) {
                let message;
                try { message = JSON.parse(event.data); } catch { return; }
                if (message.type === 'command_routed') {
                  window.clearTimeout(timeout);
                  timeout = window.setTimeout(function() {
                    socket.close();
                    reject(new Error('The device did not confirm the command.'));
                  }, 10000);
                } else if (message.type === 'device_response' && Number(message.deviceId) === Number(button.dataset.deviceId)) {
                  window.clearTimeout(timeout);
                  socket.close();
                  if (message.success === false) reject(new Error(message.message || 'The device rejected the command.'));
                  else resolve();
                } else if (message.type === 'error') {
                  window.clearTimeout(timeout);
                  socket.close();
                  reject(new Error(message.error || 'Device command failed.'));
                }
              });
              socket.addEventListener('error', function() {
                window.clearTimeout(timeout);
                reject(new Error('Could not connect to the device control channel.'));
              }, { once: true });
            });
            showAlert(deviceNotice, 'Command sent to the device.', 'success');
          } catch (error) {
            showAlert(deviceNotice, error.message || 'Unable to control device.', 'error');
          } finally {
            if (socket && socket.readyState < WebSocket.CLOSING) socket.close();
            button.disabled = false;
          }
        });
      });
    }
    function renderOverviewPanel() {
      const role = state.role;
      mainPanelTitle.textContent = role === 'admin' ? 'Admin Overview' : role === 'owner' ? 'Owner Overview' : 'Assigned Access';
      if (role === 'admin' || role === 'owner') {
        renderHouseList();
        if (state.tenants.length) {
          const panel = document.createElement('div');
          panel.className = 'card-grid';
          panel.innerHTML = state.tenants.map(function(tenant) {
            return '<div class="tenant-card"><h3>' + (tenant.name || tenant.email || 'Tenant') + '</h3><div class="meta">' + (tenant.email || 'No email') + '<br />Unit: ' + (tenant.leased_unit || 'N/A') + '<br />Rent: ' + (tenant.rent_amount || 'N/A') + '</div><div class="tag">Tenant</div></div>';
          }).join('');
          mainPanelContent.appendChild(panel);
        }
        return;
      }
      if (!state.houses.length) {
        mainPanelContent.innerHTML = '<div class="empty">No house assignment found for this account.</div>';
        return;
      }
      const cards = state.houses.map(function(house) {
        return '<div class="house-card"><div class="tag">House</div><h3>' + (house.name || 'Assigned House') + '</h3><div class="meta">' + (house.location || 'No location') + '<br />Owner: ' + (house.owner_id || 'N/A') + '</div><div class="inline-actions"><button class="mini-btn" data-house-id="' + house.id + '" data-action="select-house">View Devices</button></div></div>';
      }).join('');
      mainPanelContent.innerHTML = '<div class="card-grid">' + cards + '</div>';
      document.querySelectorAll('[data-action="select-house"]').forEach(function(btn) {
        btn.addEventListener('click', function() {
          state.selectedHouseId = Number(btn.dataset.houseId);
          state.activeView = 'devices';
          renderViewTabs();
          renderMainPanel();
        });
      });
    }
    function renderMainPanel() {
      mainPanelContent.innerHTML = '';
      if (!state.activeView || !getRoleViews().includes(state.activeView)) {
        state.activeView = 'overview';
      }
      if (state.activeView === 'houses') {
        mainPanelTitle.textContent = state.role === 'admin' ? 'All Houses' : state.role === 'owner' ? 'My Houses' : 'Assigned Houses';
        renderHouseList();
        return;
      }
      if (state.activeView === 'tenants') {
        mainPanelTitle.textContent = 'Tenants';
        renderTenantList();
        return;
      }
      if (state.activeView === 'devices') {
        mainPanelTitle.textContent = 'Devices';
        renderDeviceList();
        return;
      }
      renderOverviewPanel();
    }
    async function loadDashboardData() {
      const headers = getAuthHeaders();
      state.devices = [];
      state.fingerprints = {};
      state.tenants = [];
      try {
        const housesResponse = await fetch(API_BASE + '/api/houses', { headers: headers });
        const housesData = await housesResponse.json();
        state.houses = Array.isArray(housesData.houses) ? housesData.houses : (Array.isArray(housesData) ? housesData : []);
        if (state.role === 'admin' || state.role === 'owner') {
          const tenantsResponse = await fetch(API_BASE + '/api/tenants', { headers: headers });
          const tenantsData = await tenantsResponse.json();
          state.tenants = Array.isArray(tenantsData.tenants) ? tenantsData.tenants : [];
        }
        for (const house of state.houses) {
          const devicesResponse = await fetch(API_BASE + '/api/houses/' + house.id + '/devices', { headers: headers });
          const devicesData = await devicesResponse.json();
          if (!devicesResponse.ok) throw new Error(devicesData.error || 'Unable to load devices for house ' + house.id);
          const devices = Array.isArray(devicesData.devices) ? devicesData.devices : [];
          state.devices = state.devices.concat(devices);
        }
        await Promise.all(state.devices.map(async function(device) {
          const response = await fetch(API_BASE + '/api/devices/' + device.id + '/fingerprints', { headers: headers });
          const data = await response.json();
          if (!response.ok) throw new Error(data.error || 'Unable to load fingerprints for device ' + device.id);
          state.fingerprints[device.id] = Array.isArray(data.enrollments) ? data.enrollments : [];
        }));
        renderStats();
        renderProfile();
        renderViewTabs();
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
        const loginResponse = await requestJson(API_BASE + '/api/login', { method: 'POST', body: JSON.stringify({ email: email, password: password }) });
        state.jwt = loginResponse.accessToken;
        const meResponse = await fetch(API_BASE + '/api/me', { headers: getAuthHeaders() });
        const meData = meResponse.ok ? await meResponse.json() : null;
        if (!meData || !meData.user) throw new Error('Could not load user profile');
        state.profile = meData.user;
        state.role = String(meData.user.role || 'user').toLowerCase();
        state.activeView = 'overview';
        userDisplayName.textContent = meData.user.name || meData.user.email || 'User';
        userRole.textContent = formatRole(state.role);
        renderViewTabs();
        setActiveScreen('dashboard');
        clearAlert(passwordAlert);
        await loadDashboardData();
      } catch (error) {
        showAlert(loginAlert, error.message || 'Login failed.', 'error');
      }
    }
    async function handleLogout() {
      state.jwt = '';
      state.profile = null;
      state.role = null;
      state.houses = [];
      state.tenants = [];
      state.devices = [];
      state.fingerprints = {};
      state.selectedHouseId = null;
      state.activeView = 'overview';
      document.getElementById('email').value = 'admin@example.com';
      document.getElementById('password').value = 'AdminPass123!';
      clearAlert(loginAlert);
      clearAlert(passwordAlert);
      setActiveScreen('login');
    }
    async function handlePasswordUpdate(event) {
      event.preventDefault();
      const oldPassword = document.getElementById('oldPassword').value;
      const newPassword = document.getElementById('newPassword').value;
      if (!oldPassword || !newPassword) { showAlert(passwordAlert, 'Both current and new password are required.', 'error'); return; }
      try {
        const result = await requestJson(API_BASE + '/api/update_password', { method: 'POST', body: JSON.stringify({ token: state.jwt, oldPassword: oldPassword, newPassword: newPassword }) });
        showAlert(passwordAlert, result.message || 'Password updated successfully.', 'success');
        document.getElementById('oldPassword').value = '';
        document.getElementById('newPassword').value = '';
      } catch (error) {
        showAlert(passwordAlert, error.message || 'Password update failed.', 'error');
      }
    }
    document.getElementById('loginBtn').addEventListener('click', handleLogin);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    document.getElementById('refreshBtn').addEventListener('click', function() {
      state.devices = [];
      state.tenants = [];
      loadDashboardData();
    });
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

      if (url.pathname === '/ws/device-ticket' && request.method === 'POST') {
        return withCors(await issueDeviceWebSocketTicket(request, env), allowOrigin);
      }

      // The legacy device endpoint has no device-bound ticket and must not be used.
      if (url.pathname === '/ws/device') {
        return withCors(json({ error: 'Use the paired /ws/house/:houseId connection flow' }, 410), allowOrigin);
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
        const pathParts = url.pathname.split('/').filter(Boolean);
        const id = pathParts[2];

        if (pathParts.length === 4 && pathParts[3] === 'fingerprints' && request.method === 'GET') {
          return withCors(await listFingerprintEnrollments(env, authUser.user, id), allowOrigin);
        }

        if (pathParts.length === 5 && pathParts[3] === 'fingerprints' && pathParts[4] === 'enroll' && request.method === 'POST') {
          return withCors(await startFingerprintEnrollment(env, authUser.user, id), allowOrigin);
        }

        if (pathParts.length === 5 && pathParts[3] === 'fingerprints' && pathParts[4] === 'enroll' && request.method === 'DELETE') {
          return withCors(await cancelFingerprintEnrollment(env, authUser.user, id), allowOrigin);
        }

        if (pathParts.length === 5 && pathParts[3] === 'fingerprints' && request.method === 'DELETE') {
          return withCors(await removeFingerprintEnrollment(request, env, authUser.user, id, pathParts[4]), allowOrigin);
        }

        if (pathParts.length === 4 && pathParts[3] === 'pairing-key' && request.method === 'POST') {
          return withCors(await rotateDevicePairingKey(request, env, authUser.user, id), allowOrigin);
        }

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

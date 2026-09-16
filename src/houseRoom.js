/**
 * Durable Object for managing real-time WebSocket connections within a house
 * One HouseRoom instance per house ID
 * 
 * Handles:
 * - WebSocket lifecycle (connect, message, close)
 * - Session management with authenticated user/device metadata
 * - Message routing between web clients and IoT devices
 * - Hibernation for connection persistence
 * - Session storage with attached metadata
 */

export class HouseRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.houseId = state.id;
    this.sessions = new Map(); // sessionId → {ws, userId, clientType, deviceId, role, connectedAt}
  }

  /**
   * Accept incoming WebSocket connection
   * Validates session metadata before accepting
   */
  async fetch(request) {
    // Only accept WebSocket upgrade requests
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected WebSocket', { status: 400 });
    }

    // Extract session metadata from URL parameters or Durable Object state
    const url = new URL(request.url);
    const sessionId = url.searchParams.get('sessionId');
    const userId = url.searchParams.get('userId');
    const clientType = url.searchParams.get('clientType') || 'web';
    const deviceId = url.searchParams.get('deviceId');
    const role = url.searchParams.get('role');

    // Validate required fields (should already be validated by ticket system)
    if (!sessionId || !userId) {
      return new Response('Invalid session', { status: 401 });
    }

    // Create WebSocket pair
    const [clientWs, serverWs] = new WebSocketPair();

    // Store session with metadata
    const session = {
      ws: serverWs,
      userId: parseInt(userId),
      clientType: clientType, // 'web' or 'device'
      deviceId: deviceId ? parseInt(deviceId) : null,
      role: role || 'user',
      connectedAt: new Date().toISOString(),
      lastMessageAt: new Date().toISOString()
    };

    this.sessions.set(sessionId, session);

    // Use WebSocket Hibernation for better resource usage
    serverWs.accept();

    // Set up message handler
    serverWs.onmessage = (event) => this.handleMessage(sessionId, event);
    serverWs.onclose = () => this.handleClose(sessionId);
    serverWs.onerror = (error) => this.handleError(sessionId, error);

    // Notify other clients that someone connected
    this.broadcastSystemMessage({
      type: 'user_joined',
      sessionId,
      userId,
      clientType,
      timestamp: new Date().toISOString()
    }, sessionId);

    // Send welcome message
    serverWs.send(JSON.stringify({
      type: 'connected',
      sessionId,
      houseId: this.houseId,
      message: `Connected to house room`,
      timestamp: new Date().toISOString()
    }));

    return new Response(null, { status: 101, webSocket: clientWs });
  }

  /**
   * Handle incoming messages from clients
   */
  async handleMessage(sessionId, event) {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.lastMessageAt = new Date().toISOString();

    try {
      const message = JSON.parse(event.data);

      // Validate message format
      if (!message.type) {
        session.ws.send(JSON.stringify({
          type: 'error',
          error: 'Message must have a type field',
          timestamp: new Date().toISOString()
        }));
        return;
      }

      // Handle different message types
      switch (message.type) {
        case 'ping':
          this.handlePing(sessionId, session, message);
          break;

        case 'pong':
          // Client responded to ping, update last seen
          session.lastMessageAt = new Date().toISOString();
          break;

        case 'device_command':
          // Command from web client to device
          if (session.clientType === 'web') {
            this.handleDeviceCommand(sessionId, session, message);
          } else {
            session.ws.send(JSON.stringify({
              type: 'error',
              error: 'Only web clients can send device commands',
              timestamp: new Date().toISOString()
            }));
          }
          break;

        case 'device_update':
          // Status update from device
          if (session.clientType === 'device') {
            this.handleDeviceUpdate(sessionId, session, message);
          } else {
            session.ws.send(JSON.stringify({
              type: 'error',
              error: 'Only devices can send device updates',
              timestamp: new Date().toISOString()
            }));
          }
          break;

        case 'get_devices':
          // Request list of connected devices
          this.handleGetDevices(sessionId, session);
          break;

        case 'get_sessions':
          // Admin: get all connected sessions (admin only)
          if (session.role === 'admin') {
            this.handleGetSessions(sessionId, session);
          } else {
            session.ws.send(JSON.stringify({
              type: 'error',
              error: 'Permission denied',
              timestamp: new Date().toISOString()
            }));
          }
          break;

        default:
          session.ws.send(JSON.stringify({
            type: 'error',
            error: `Unknown message type: ${message.type}`,
            timestamp: new Date().toISOString()
          }));
      }
    } catch (error) {
      console.error(`[HouseRoom ${this.houseId}] Message handling error:`, error);
      session.ws.send(JSON.stringify({
        type: 'error',
        error: 'Failed to process message',
        timestamp: new Date().toISOString()
      }));
    }
  }

  /**
   * Handle ping message (keep-alive)
   */
  handlePing(sessionId, session, message) {
    session.ws.send(JSON.stringify({
      type: 'pong',
      timestamp: new Date().toISOString(),
      requestId: message.requestId
    }));
  }

  /**
   * Handle command from web client to device
   * Format: { type: 'device_command', targetDeviceId: 123, command: 'unlock', params: {...} }
   */
  handleDeviceCommand(sessionId, session, message) {
    const { targetDeviceId, command, params } = message;

    if (!targetDeviceId || !command) {
      session.ws.send(JSON.stringify({
        type: 'error',
        error: 'device_command requires targetDeviceId and command',
        timestamp: new Date().toISOString()
      }));
      return;
    }

    // Find device session(s)
    const deviceSessions = Array.from(this.sessions.entries())
      .filter(([id, sess]) => sess.clientType === 'device' && sess.deviceId === targetDeviceId);

    if (deviceSessions.length === 0) {
      session.ws.send(JSON.stringify({
        type: 'error',
        error: `Device ${targetDeviceId} not connected`,
        timestamp: new Date().toISOString()
      }));
      return;
    }

    // Route command to device(s)
    const commandMessage = {
      type: 'device_command',
      command,
      params: params || {},
      fromUserId: session.userId,
      fromSessionId: sessionId,
      timestamp: new Date().toISOString()
    };

    deviceSessions.forEach(([deviceSessionId, deviceSession]) => {
      try {
        deviceSession.ws.send(JSON.stringify(commandMessage));
      } catch (error) {
        console.error(`Failed to send command to device session ${deviceSessionId}:`, error);
      }
    });

    // Send confirmation to command sender
    session.ws.send(JSON.stringify({
      type: 'command_routed',
      targetDeviceId,
      command,
      timestamp: new Date().toISOString()
    }));
  }

  /**
   * Handle device status update
   * Format: { type: 'device_update', deviceId: 123, status: 'online', data: {...} }
   */
  handleDeviceUpdate(sessionId, session, message) {
    const { deviceId, status, data } = message;

    if (!deviceId) {
      session.ws.send(JSON.stringify({
        type: 'error',
        error: 'device_update requires deviceId',
        timestamp: new Date().toISOString()
      }));
      return;
    }

    // Broadcast device update to all web clients
    const updateMessage = {
      type: 'device_update',
      deviceId,
      status: status || 'online',
      data: data || {},
      fromDeviceSessionId: sessionId,
      timestamp: new Date().toISOString()
    };

    this.broadcastToClients(updateMessage, sessionId, 'web');
  }

  /**
   * Handle request for list of connected devices
   */
  handleGetDevices(sessionId, session) {
    const devices = Array.from(this.sessions.values())
      .filter(sess => sess.clientType === 'device')
      .map(sess => ({
        deviceId: sess.deviceId,
        connectedAt: sess.connectedAt,
        lastMessageAt: sess.lastMessageAt
      }));

    session.ws.send(JSON.stringify({
      type: 'devices_list',
      devices,
      timestamp: new Date().toISOString()
    }));
  }

  /**
   * Handle admin request for all sessions (admin only)
   */
  handleGetSessions(sessionId, session) {
    const sessions = Array.from(this.sessions.entries())
      .map(([id, sess]) => ({
        sessionId: id,
        userId: sess.userId,
        clientType: sess.clientType,
        deviceId: sess.deviceId,
        role: sess.role,
        connectedAt: sess.connectedAt,
        lastMessageAt: sess.lastMessageAt
      }));

    session.ws.send(JSON.stringify({
      type: 'sessions_list',
      sessions,
      timestamp: new Date().toISOString()
    }));
  }

  /**
   * Handle WebSocket close event
   */
  handleClose(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    this.sessions.delete(sessionId);

    // Notify other clients
    this.broadcastSystemMessage({
      type: 'user_left',
      sessionId,
      userId: session.userId,
      clientType: session.clientType,
      timestamp: new Date().toISOString()
    });

    console.log(`[HouseRoom ${this.houseId}] Session ${sessionId} (user ${session.userId}) disconnected`);
  }

  /**
   * Handle WebSocket error
   */
  handleError(sessionId, error) {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    console.error(`[HouseRoom ${this.houseId}] WebSocket error for session ${sessionId}:`, error);

    try {
      session.ws.send(JSON.stringify({
        type: 'error',
        error: 'WebSocket error occurred',
        timestamp: new Date().toISOString()
      }));
    } catch {
      // Connection might be closed
    }

    this.handleClose(sessionId);
  }

  /**
   * Broadcast message to all clients except sender
   */
  broadcastToClients(message, excludeSessionId = null, filterClientType = null) {
    const messageStr = JSON.stringify(message);

    this.sessions.forEach((session, sessionId) => {
      // Skip sender
      if (excludeSessionId && sessionId === excludeSessionId) return;

      // Filter by client type if specified
      if (filterClientType && session.clientType !== filterClientType) return;

      try {
        session.ws.send(messageStr);
      } catch (error) {
        console.error(`Failed to broadcast to session ${sessionId}:`, error);
      }
    });
  }

  /**
   * Broadcast system message to all clients
   */
  broadcastSystemMessage(message, excludeSessionId = null) {
    this.broadcastToClients(message, excludeSessionId);
  }

  /**
   * Scheduled cleanup of old sessions (optional, for Durable Object alarms)
   */
  async alarm() {
    const now = new Date();
    const staleThreshold = 5 * 60 * 1000; // 5 minutes

    for (const [sessionId, session] of this.sessions.entries()) {
      const timeSinceLastMessage = now - new Date(session.lastMessageAt);
      if (timeSinceLastMessage > staleThreshold) {
        try {
          session.ws.close(1000, 'Inactivity timeout');
        } catch {
          // Already closed
        }
        this.sessions.delete(sessionId);
      }
    }

    // Schedule next alarm
    this.state.storage.setAlarm(Date.now() + 60 * 1000); // Check every minute
  }
}

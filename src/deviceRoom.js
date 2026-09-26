import { DurableObject } from "cloudflare:workers";

export class DeviceRoom extends DurableObject {

  constructor(ctx, env) {
    super(ctx, env);

    this.ctx = ctx;
    this.env = env;

    console.log("[DEVICE-ROOM] Durable Object initialized");
  }

  // ==========================================================
  // WEBSOCKET CONNECTION
  // ==========================================================

  async fetch(request) {

    const upgrade =
      request.headers.get("Upgrade");

    if (!upgrade ||
        upgrade.toLowerCase() !== "websocket") {

      return new Response(
        "Expected WebSocket upgrade",
        {
          status: 426
        }
      );
    }

    console.log(
      "[DEVICE-ROOM] WebSocket connection request"
    );

    // --------------------------------------------------------
    // Create WebSocket pair
    // --------------------------------------------------------

    const webSocketPair =
      new WebSocketPair();

    const [client, server] =
      Object.values(webSocketPair);

    // --------------------------------------------------------
    // Accept using Durable Object Hibernation API
    // --------------------------------------------------------

    this.ctx.acceptWebSocket(server);

    console.log(
      "[DEVICE-ROOM] WebSocket accepted"
    );

    // --------------------------------------------------------
    // Send connection confirmation
    // --------------------------------------------------------

    server.send(
      JSON.stringify({
        type: "connected",
        success: true,
        message: "DeviceRoom WebSocket connected",
        timestamp: Date.now()
      })
    );

    // --------------------------------------------------------
    // Return WebSocket response
    // --------------------------------------------------------

    return new Response(
      null,
      {
        status: 101,
        webSocket: client
      }
    );
  }

  // ==========================================================
  // MESSAGE
  // ==========================================================

  async webSocketMessage(
    ws,
    message
  ) {

    console.log(
      "[DEVICE-ROOM] Message received:",
      message
    );

    let parsed;

    // --------------------------------------------------------
    // Parse JSON
    // --------------------------------------------------------

    try {

      parsed =
        JSON.parse(message);

    } catch (error) {

      console.error(
        "[DEVICE-ROOM] Invalid JSON:",
        error
      );

      ws.send(
        JSON.stringify({
          success: false,
          type: "response",
          error: "Invalid JSON",
          timestamp: Date.now()
        })
      );

      return;
    }

    // --------------------------------------------------------
    // Stage 1.5 echo response
    // --------------------------------------------------------

    const response = {

      success: true,

      type: "response",

      message:
        "Message received by DeviceRoom",

      received: parsed,

      timestamp: Date.now()

    };

    ws.send(
      JSON.stringify(response)
    );

    console.log(
      "[DEVICE-ROOM] Response sent"
    );
  }

  // ==========================================================
  // CLOSE
  // ==========================================================

  async webSocketClose(
    ws,
    code,
    reason,
    wasClean
  ) {

    console.log(
      "[DEVICE-ROOM] WebSocket closed:",
      code,
      reason || "",
      "clean:",
      wasClean
    );
  }

  // ==========================================================
  // ERROR
  // ==========================================================

  async webSocketError(
    ws,
    error
  ) {

    console.error(
      "[DEVICE-ROOM] WebSocket error:",
      error
    );
  }
}
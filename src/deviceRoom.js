import { DurableObject } from "cloudflare:workers";

export class DeviceRoom extends DurableObject {

  constructor(ctx, env) {
    super(ctx, env);

    this.ctx = ctx;
    this.env = env;

    console.log("[DEVICE-ROOM] Durable Object initialized");
  }

  async fetch(request) {

    const upgrade = request.headers.get("Upgrade");

    if (!upgrade || upgrade.toLowerCase() !== "websocket") {
      return new Response(
        "Expected WebSocket upgrade",
        { status: 426 }
      );
    }

    const userAgent =
      request.headers.get("User-Agent") || "";

    const isDevice =
      userAgent.includes("arduino-WebSocket-Client");

    const role = isDevice
      ? "device"
      : "browser";

    console.log(
      `[DEVICE-ROOM] WebSocket connection request: ${role}`
    );

    const webSocketPair = new WebSocketPair();

    const [client, server] =
      Object.values(webSocketPair);

    this.ctx.acceptWebSocket(server);

    // Store connection role so it survives DO hibernation.
    server.serializeAttachment({
      role,
      connectedAt: Date.now()
    });

    console.log(
      `[DEVICE-ROOM] WebSocket accepted: ${role}`
    );

    server.send(
      JSON.stringify({
        type: "connected",
        success: true,
        role,
        message:
          role === "device"
            ? "DeviceRoom WebSocket connected"
            : "Browser control WebSocket connected",
        timestamp: Date.now()
      })
    );

    return new Response(null, {
      status: 101,
      webSocket: client
    });
  }

  async webSocketMessage(ws, message) {

    const connection =
      ws.deserializeAttachment();

    const role =
      connection?.role || "unknown";

    console.log(
      `[DEVICE-ROOM] Message from ${role}:`,
      message
    );

    let parsed;

    try {

      parsed = JSON.parse(message);

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

    /*
     * ========================================================
     * BROWSER → ESP32
     * ========================================================
     */

    if (role === "browser") {

      console.log(
        "[DEVICE-ROOM] Browser command received"
      );

      const deviceSockets =
        this.ctx.getWebSockets().filter(
          socket => {

            const attachment =
              socket.deserializeAttachment();

            return attachment?.role === "device";
          }
        );

      console.log(
        `[DEVICE-ROOM] Connected devices: ${deviceSockets.length}`
      );

      if (deviceSockets.length === 0) {

        ws.send(
          JSON.stringify({
            success: false,
            type: "error",
            message: "No ESP32 device connected",
            timestamp: Date.now()
          })
        );

        return;
      }

      const commandMessage =
        JSON.stringify(parsed);

      for (const device of deviceSockets) {

        try {

          device.send(commandMessage);

          console.log(
            "[DEVICE-ROOM] Command sent to ESP32"
          );

        } catch (error) {

          console.error(
            "[DEVICE-ROOM] Failed sending to ESP32:",
            error
          );

        }
      }

      /*
       * Tell browser that Cloudflare accepted
       * the command.
       */

      ws.send(
        JSON.stringify({
          success: true,
          type: "command_sent",
          message: "Command sent to ESP32",
          command: parsed,
          timestamp: Date.now()
        })
      );

      return;
    }

    /*
     * ========================================================
     * ESP32 → BROWSER
     * ========================================================
     */

    if (role === "device") {

      console.log(
        "[DEVICE-ROOM] Response received from ESP32"
      );

      const browserSockets =
        this.ctx.getWebSockets().filter(
          socket => {

            const attachment =
              socket.deserializeAttachment();

            return attachment?.role === "browser";
          }
        );

      console.log(
        `[DEVICE-ROOM] Connected browsers: ${browserSockets.length}`
      );

      for (const browser of browserSockets) {

        try {

          browser.send(
            JSON.stringify({
              type: "device_response",
              deviceMessage: parsed,
              timestamp: Date.now()
            })
          );

        } catch (error) {

          console.error(
            "[DEVICE-ROOM] Failed sending to browser:",
            error
          );

        }
      }

      return;
    }

    /*
     * ========================================================
     * UNKNOWN CONNECTION
     * ========================================================
     */

    ws.send(
      JSON.stringify({
        success: false,
        type: "error",
        message: "Unknown connection role",
        timestamp: Date.now()
      })
    );
  }

  async webSocketClose(
    ws,
    code,
    reason,
    wasClean
  ) {

    const connection =
      ws.deserializeAttachment();

    console.log(
      "[DEVICE-ROOM] WebSocket closed:",
      connection?.role || "unknown",
      code,
      reason || "",
      "clean:",
      wasClean
    );
  }

  async webSocketError(ws, error) {

    const connection =
      ws.deserializeAttachment();

    console.error(
      "[DEVICE-ROOM] WebSocket error:",
      connection?.role || "unknown",
      error
    );
  }
}
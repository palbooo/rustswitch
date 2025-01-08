require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const SteamStrategy = require("passport-steam").Strategy;
const path = require("path");
const WebSocket = require("ws");
const RustPlus = require("@liamcottle/rustplus.js");
const AndroidFCM = require("@liamcottle/push-receiver/src/android/fcm");
const PushReceiverClient = require("@liamcottle/push-receiver/src/client");
const mongoose = require("mongoose");
const { connectDB, Switch, SwitchLog } = require("./models/db");

const app = express();
const server = require("http").createServer(app);
const wss = new WebSocket.Server({ noServer: true });

// Erstelle den sessionParser einmal global
const sessionParser = session({
  secret: process.env.SESSION_SECRET || "your-secret-key",
  resave: false,
  saveUninitialized: false,
});

// Global RustPlus instance
let rustplusInstance = null;
let isConnected = false;

// Connect to MongoDB
connectDB();

// Neue globale Variablen für Playground
let playgroundSettings = {
  enabled: false,
  cooldown: 30, // Standardmäßig 30 Sekunden Cooldown
};
let bannedUsers = new Set();
const userCooldowns = new Map();

// Lade Playground-Einstellungen
try {
  const settings = require("./playground_settings.json");
  playgroundSettings = settings;
  bannedUsers = new Set(settings.bannedUsers || []);
} catch (err) {
  console.log("No saved playground settings found");
}

// Funktion zum Speichern der Playground-Einstellungen
const savePlaygroundSettings = () => {
  require("fs").writeFileSync(
    "playground_settings.json",
    JSON.stringify(
      {
        ...playgroundSettings,
        bannedUsers: Array.from(bannedUsers),
      },
      null,
      2
    )
  );
};

// Session configuration
app.use(sessionParser);

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Steam Strategy configuration
passport.use(
  new SteamStrategy(
    {
      returnURL: `${process.env.APP_URL}/auth/steam/return`,
      realm: `${process.env.APP_URL}/`,
      apiKey: process.env.STEAM_API_KEY,
    },
    function (identifier, profile, done) {
      return done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/auth/steam");
};

// Global variables
let adminIds = new Set(
  process.env.ADMIN_STEAM_IDS ? process.env.ADMIN_STEAM_IDS.split(",") : []
);
let editIds = new Set();
let rustPlusConfigs = new Map();
let fcmClient = null;
let fcmConfig = null;

// Load configurations
try {
  const configs = require("./rustplus_configs.json");
  rustPlusConfigs = new Map(Object.entries(configs));
} catch (err) {
  console.log("No saved RustPlus configurations found");
}

try {
  fcmConfig = require("./rustplus.config.json");
} catch (err) {
  console.log("No FCM configuration found");
}

try {
  const savedEditIds = require("./editIds.json");
  editIds = new Set(savedEditIds);
} catch (err) {
  console.log("No saved edit IDs found");
}

// Save functions
const saveRustPlusConfigs = () => {
  const configsObj = Object.fromEntries(rustPlusConfigs);
  require("fs").writeFileSync(
    "rustplus_configs.json",
    JSON.stringify(configsObj, null, 2)
  );
};

const saveEditIds = () => {
  require("fs").writeFileSync("editIds.json", JSON.stringify([...editIds]));
};

// Initialize the RustPlus connection
async function initializeRustPlus(serverId) {
  // Get the specific config for this server
  const config = rustPlusConfigs.get(serverId);
  if (!config) {
    throw new Error(`Keine Server-Konfiguration gefunden für ${serverId}`);
  }

  // Create a new instance for this server if it doesn't exist
  if (!rustplusInstance || rustplusInstance.serverId !== serverId) {
    // Disconnect existing instance if it exists
    if (rustplusInstance) {
      rustplusInstance.disconnect();
    }

    rustplusInstance = new RustPlus(
      config.ip,
      config.port,
      config.playerId,
      config.playerToken
    );
    rustplusInstance.serverId = serverId; // Add serverId to track which server this instance is for

    // Set up event handlers
    rustplusInstance.on("connected", () => {
      console.log(`RustPlus connection established for server ${serverId} `);
      console.log(config.playerToken);

      isConnected = true;
    });

    rustplusInstance.on("disconnected", () => {
      console.log(
        `RustPlus connection disconnected for server ${serverId}, trying to reconnect...`
      );
      isConnected = false;
      // Try to reconnect after 5 seconds
      setTimeout(() => {
        if (!isConnected && rustplusInstance) {
          rustplusInstance.connect();
        }
      }, 5000);
    });

    rustplusInstance.on("error", (err) => {
      console.error(`RustPlus error for server ${serverId}:`, err);
      isConnected = false;
    });

    // Initial connection
    console.log(`Connecting to RustPlus Server ${serverId}...`);
    rustplusInstance.connect();
  }

  return rustplusInstance;
}

// FCM Listener Functions
async function startFCMListener() {
  if (!fcmConfig || !fcmConfig.fcm_credentials) {
    console.error("FCM Credentials missing. Please run fcm-register first");
    return;
  }

  console.log("Starting FCM Listener for Pairing Notifications...");
  const androidId = fcmConfig.fcm_credentials.gcm.androidId;
  const securityToken = fcmConfig.fcm_credentials.gcm.securityToken;

  fcmClient = new PushReceiverClient(androidId, securityToken, []);

  fcmClient.on("ON_DATA_RECEIVED", (data) => {
    const timestamp = new Date().toLocaleString();
    console.log("\x1b[32m%s\x1b[0m", `[${timestamp}] Notification Received`);
    console.log(data);
    handlePairingNotification(data);
  });

  await fcmClient.connect();
  console.log("FCM Listener successfully started");
}

async function handlePairingNotification(data) {
  try {
    const notification = data.appData.find((item) => item.key === "body");
    if (!notification) {
      console.log("No body notification found");
      return;
    }

    const notificationData = JSON.parse(notification.value);
    console.log("Parsed notification data:", notificationData);

    const serverId = `${notificationData.ip}:${notificationData.port}`;
    console.log("Server ID:", serverId);

    // Check if all required fields for server configuration are present
    const hasAllServerConfig =
      notificationData.ip &&
      notificationData.port &&
      notificationData.playerId &&
      notificationData.playerToken;

    // Only update server configuration if all required fields are present
    if (hasAllServerConfig) {
      console.log(
        "All server configuration data present, updating configuration"
      );

      const updatedConfig = {
        ip: notificationData.ip,
        port: notificationData.port,
        playerId: notificationData.playerId,
        playerToken: notificationData.playerToken,
      };

      // Save the updated configuration
      rustPlusConfigs.set(serverId, updatedConfig);
      saveRustPlusConfigs();
      console.log("Server configuration updated:", {
        serverId,
        config: updatedConfig,
      });

      // Initialize new connection with updated configuration if needed
      if (rustplusInstance && rustplusInstance.serverId === serverId) {
        console.log("Restarting connection with updated token...");
        await initializeRustPlus(serverId);
      }
    } else {
      console.log("Incomplete server configuration data, skipping update");
    }

    // Process Smart Switch independently of server config
    if (
      notificationData.type === "entity" &&
      notificationData.entityType === "1" &&
      notificationData.entityId // Make sure entityId exists
    ) {
      const switchId = `${serverId}-${notificationData.entityId}`;
      console.log("Processing switch with ID:", switchId);

      const switchConfig = {
        id: switchId,
        switchId,
        serverId: serverId,
        entityId: notificationData.entityId,
        name: notificationData.entityName || "Smart Switch",
        lastState: false,
      };

      // Notify all admin clients about the new switch
      wss.clients.forEach((client) => {
        if (
          client.readyState === WebSocket.OPEN &&
          (client.userInfo?.role === "admin" ||
            client.userInfo?.role === "edit")
        ) {
          try {
            const message = {
              type: "addSwitch",
              switch: switchConfig,
            };
            console.log("Sending message to client:", message);
            client.send(JSON.stringify(message));
          } catch (err) {
            console.error(
              `Error sending to client ${client.userInfo?.steamId}:`,
              err
            );
          }
        }
      });
    }
  } catch (error) {
    console.error("Error processing pairing notification:", error);
    console.error(error.stack);
  }
}

async function toggleSmartSwitch(ip, port, entityId, state) {
  try {
    const serverId = `${ip}:${port}`;
    console.log(
      `Attempting to toggle switch for server ${serverId}, EntityID: ${entityId}`
    );

    // Überprüfe ob die Server-Konfiguration existiert
    const config = rustPlusConfigs.get(serverId);
    console.log("Current server configuration:", {
      serverId,
      config,
    });
    if (!config) {
      throw new Error(`No configuration found for server ${serverId}`);
    }

    // Verbindung zum richtigen Server herstellen
    if (
      !rustplusInstance ||
      rustplusInstance.serverId !== serverId ||
      !isConnected
    ) {
      console.log(`Initializing new connection to server ${serverId}`);
      await initializeRustPlus(serverId);

      // Warte auf Verbindung
      if (!isConnected) {
        console.log("Waiting for connection...");
        await new Promise((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error("Connection timeout"));
          }, 10000);

          const checkConnection = setInterval(() => {
            if (isConnected) {
              clearInterval(checkConnection);
              clearTimeout(timeout);
              resolve();
            }
          }, 100);
        });
      }
    }

    console.log(
      `Toggling switch ${entityId} on Server ${serverId} ${
        state ? "on" : "off"
      }...`
    );

    // Sende den Befehl
    return new Promise((resolve, reject) => {
      const parsedEntityId = parseInt(entityId);

      const commandFunction = state
        ? rustplusInstance.turnSmartSwitchOn.bind(rustplusInstance)
        : rustplusInstance.turnSmartSwitchOff.bind(rustplusInstance);

      commandFunction(parsedEntityId, (message) => {
        console.log("Switch response received:", message);
        if (message.response && message.response.error) {
          console.error(`Error from server: ${message.response.error.error}`);
          reject(new Error(message.response.error.error));
        } else {
          console.log("Switch successfully toggled");
          resolve(message);
        }
      });
    });
  } catch (error) {
    console.error("Error while toggling:", error);
    throw error;
  }
}

// Routes
app.get("/auth/steam", passport.authenticate("steam"));

app.get(
  "/auth/steam/return",
  passport.authenticate("steam", { failureRedirect: "/" }),
  (req, res) => {
    const steamId = req.user.id;

    // Prüfe ob User gebannt ist
    if (bannedUsers.has(steamId)) {
      return res.status(403).send("You are banned and cannot use this service");
    }

    if (adminIds.has(steamId)) {
      res.redirect("/admin");
    } else if (editIds.has(steamId)) {
      res.redirect("/edit");
    } else {
      res.redirect("/playground");
    }
  }
);

// Add this route before other routes
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    // If user is already logged in, redirect based on role
    const steamId = req.user.id;
    if (adminIds.has(steamId)) {
      res.redirect("/admin");
    } else if (editIds.has(steamId)) {
      res.redirect("/edit");
    } else {
      res.redirect("/playground");
    }
  } else {
    // If not logged in, show the login page
    res.sendFile(path.join(__dirname, "public", "index.html"));
  }
});

app.get("/admin", isAuthenticated, (req, res) => {
  if (!adminIds.has(req.user.id)) {
    return res.redirect("/playground");
  }
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/edit", isAuthenticated, (req, res) => {
  if (!editIds.has(req.user.id) && !adminIds.has(req.user.id)) {
    return res.redirect("/playground");
  }
  res.sendFile(path.join(__dirname, "public", "edit.html"));
});

app.get("/playground", isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "playground.html"));
});

// API Endpoints
app.use(express.json());

app.get("/api/switches", isAuthenticated, async (req, res) => {
  if (!adminIds.has(req.user.id) && !editIds.has(req.user.id)) {
    return res.status(403).json({ error: "No permission" });
  }

  try {
    const switches = await Switch.find({});
    res.json(switches);
  } catch (error) {
    console.error("Error loading switches:", error);
    res.status(500).json({ error: "Error loading switches" });
  }
});

app.get("/api/edit-ids", isAuthenticated, (req, res) => {
  if (!adminIds.has(req.user.id)) {
    return res.status(403).json({ error: "No permission" });
  }
  res.json([...editIds]);
});

// Get switch logs
app.get("/api/switch-logs", isAuthenticated, async (req, res) => {
  if (!adminIds.has(req.user.id)) {
    return res.status(403).json({ error: "No permission" });
  }

  try {
    const logs = await SwitchLog.find({}).sort({ timestamp: -1 }).limit(100); // Limit to last 100 entries
    res.json(logs);
  } catch (error) {
    console.error("Error loading switch logs:", error);
    res.status(500).json({ error: "Error loading switch logs" });
  }
});

// Playground Settings API
app.get("/api/playground-settings", isAuthenticated, (req, res) => {
  if (!adminIds.has(req.user.id)) {
    return res.status(403).json({ error: "No permission" });
  }
  res.json({
    enabled: playgroundSettings.enabled,
    cooldown: playgroundSettings.cooldown,
    bannedUsers: Array.from(bannedUsers),
  });
});

app.post("/api/playground-settings", isAuthenticated, (req, res) => {
  if (!adminIds.has(req.user.id)) {
    return res.status(403).json({ error: "No permission" });
  }

  if (typeof req.body.enabled === "boolean") {
    playgroundSettings.enabled = req.body.enabled;
  }
  if (typeof req.body.cooldown === "number" && req.body.cooldown >= 0) {
    playgroundSettings.cooldown = req.body.cooldown;
  }

  savePlaygroundSettings();
  res.json({ success: true });
});

// Banned Users API
app.post("/api/banned-users", isAuthenticated, (req, res) => {
  if (!adminIds.has(req.user.id)) {
    return res.status(403).json({ error: "No permission" });
  }

  const { steamId, action } = req.body;

  if (action === "ban") {
    bannedUsers.add(steamId);
  } else if (action === "unban") {
    bannedUsers.delete(steamId);
  }

  savePlaygroundSettings();
  res.json({ success: true });
});

app.post("/api/edit-ids", isAuthenticated, express.json(), (req, res) => {
  if (!adminIds.has(req.user.id)) {
    return res.status(403).json({ error: "No permission" });
  }

  const { steamId, action } = req.body;
  if (action === "add") {
    editIds.add(steamId);
  } else if (action === "remove") {
    editIds.delete(steamId);
  }

  saveEditIds();
  res.json({ success: true });
});

// WebSocket handling
// WebSocket handling
wss.on("connection", function connection(ws, req) {
  const userSteamId = req.user?.id;
  if (!userSteamId) {
    console.log("Connection rejected: No user ID");
    ws.close(4001, "Not authenticated");
    return;
  }

  // Set up ping interval
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping();
    }
  }, 15000); // Send ping every 15 seconds

  // Clear interval on close
  ws.on("close", () => {
    clearInterval(pingInterval);
  });

  let userRole = "playground";
  if (adminIds.has(userSteamId)) {
    userRole = "admin";
  } else if (editIds.has(userSteamId)) {
    userRole = "edit";
  }

  ws.userInfo = {
    steamId: userSteamId,
    role: userRole,
    steamName: req.user.displayName,
    avatarUrl: req.user._json.avatarmedium,
  };

  console.log(`New client connected: ${userRole}, ID: ${userSteamId}`);

  ws.send(
    JSON.stringify({
      type: "auth",
      status: "success",
      role: userRole,
    })
  );

  ws.on("message", async function incoming(message) {
    try {
      const data = JSON.parse(message);
      const userSteamId = ws.userInfo?.steamId;

      if (data.type === "ping") {
        ws.send(
          JSON.stringify({
            type: "pong",
            timestamp: Date.now(),
          })
        );
        return;
      }

      // Prüfe zuerst ob User gebannt ist
      if (bannedUsers.has(userSteamId)) {
        ws.send(
          JSON.stringify({
            type: "error",
            message: "Du bist gebannt und kannst diesen Service nicht nutzen",
          })
        );
        return;
      }

      console.log(
        "Received message:",
        data.type,
        "from role:",
        ws.userInfo?.role
      );

      switch (data.type) {
        case "loadSwitches":
          // Erlaube Laden der Switches für alle Rollen wenn Playground aktiv
          if (
            ws.userInfo?.role === "playground" &&
            !playgroundSettings.enabled
          ) {
            ws.send(
              JSON.stringify({
                type: "error",
                message: "Playground is disabled",
              })
            );
            return;
          }
          try {
            const switches = await Switch.find({});
            ws.send(
              JSON.stringify({
                type: "switchesLoaded",
                switches: switches,
              })
            );
          } catch (error) {
            console.error("Fehler beim Laden der Switches:", error);
            ws.send(
              JSON.stringify({
                type: "error",
                message: "Fehler beim Laden der Switches",
              })
            );
          }
          break;

        case "toggleSwitch":
          // Prüfe Berechtigungen und Playground-Status
          if (ws.userInfo?.role === "playground") {
            if (!playgroundSettings.enabled) {
              ws.send(
                JSON.stringify({
                  type: "error",
                  message: "Playground ist deaktiviert",
                })
              );
              return;
            }

            // Prüfe Cooldown
            const lastUse = userCooldowns.get(userSteamId) || 0;
            const now = Date.now();
            const cooldownTime = playgroundSettings.cooldown * 1000;

            if (now - lastUse < cooldownTime) {
              const remainingTime = Math.ceil(
                (cooldownTime - (now - lastUse)) / 1000
              );
              ws.send(
                JSON.stringify({
                  type: "error",
                  message: `Please wait ${remainingTime} seconds`,
                })
              );
              return;
            }

            userCooldowns.set(userSteamId, now);
          } else if (
            ws.userInfo?.role !== "admin" &&
            ws.userInfo?.role !== "edit"
          ) {
            ws.send(
              JSON.stringify({
                type: "error",
                message: "No permission",
              })
            );
            return;
          }

          // Toggle Switch Logik
          const { switchId, state } = data;
          try {
            const switchDoc = await Switch.findOne({ switchId });

            if (switchDoc) {
              const [ip, port] = switchDoc.serverId.split(":");
              const config = rustPlusConfigs.get(switchDoc.serverId);

              if (config) {
                await toggleSmartSwitch(ip, port, switchDoc.entityId, state);

                // Update state in database
                switchDoc.lastState = state;
                await switchDoc.save();

                const switchLog = new SwitchLog({
                  switchId: switchId,
                  steamId: ws.userInfo.steamId,
                  steamName: ws.userInfo.steamName,
                  avatarUrl: ws.userInfo.avatarUrl,
                  state: state,
                });
                await switchLog.save();

                // Notify all clients about the state change
                wss.clients.forEach((client) => {
                  if (client.readyState === WebSocket.OPEN) {
                    client.send(
                      JSON.stringify({
                        type: "switchStateChanged",
                        switchId: switchId,
                        state: state,
                      })
                    );
                  }
                });
              }
            }
          } catch (error) {
            console.error("Fehler beim Schalten:", error);
            ws.send(
              JSON.stringify({
                type: "error",
                message: "Error toggling the switch",
              })
            );
          }
          break;

        case "confirmSwitch":
          if (ws.userInfo?.role !== "admin") {
            ws.send(
              JSON.stringify({
                type: "error",
                message: "No permission",
              })
            );
            return;
          }

          const { switchData, position } = data;
          const [row, col] = position.split("-").map(Number);

          try {
            const existingAtPosition = await Switch.findOne({
              "position.row": row,
              "position.col": col,
            });

            if (existingAtPosition) {
              ws.send(
                JSON.stringify({
                  type: "error",
                  message: "Position already occupied",
                })
              );
              return;
            }

            const newSwitch = new Switch({
              switchId: switchData.id,
              serverId: switchData.serverId,
              entityId: switchData.entityId,
              name: switchData.name,
              position: { row, col },
              lastState: false,
            });

            await newSwitch.save();

            wss.clients.forEach((client) => {
              if (
                client.readyState === WebSocket.OPEN &&
                (client.userInfo?.role === "admin" ||
                  client.userInfo?.role === "edit")
              ) {
                client.send(
                  JSON.stringify({
                    type: "addedSwitch",
                    switch: {
                      ...switchData,
                      position: { row, col },
                    },
                    position: position,
                  })
                );
              }
            });
          } catch (error) {
            console.error("Error saving the switch:", error);
            ws.send(
              JSON.stringify({
                type: "error",
                message: "Error saving the switch",
              })
            );
          }
          break;

        case "removeSwitch":
          if (ws.userInfo?.role !== "admin") {
            ws.send(
              JSON.stringify({
                type: "error",
                message: "No permission",
              })
            );
            return;
          }

          const { switchIdToRemove } = data;
          try {
            const removedSwitch = await Switch.findOneAndDelete({
              switchId: switchIdToRemove,
            });
            if (removedSwitch) {
              wss.clients.forEach((client) => {
                if (
                  client.readyState === WebSocket.OPEN &&
                  (client.userInfo?.role === "admin" ||
                    client.userInfo?.role === "edit")
                ) {
                  client.send(
                    JSON.stringify({
                      type: "switchRemoved",
                      switchId: switchIdToRemove,
                    })
                  );
                }
              });
            } else {
              ws.send(
                JSON.stringify({
                  type: "error",
                  message: "Switch not found",
                })
              );
            }
          } catch (error) {
            console.error("Error removing the switch:", error);
            ws.send(
              JSON.stringify({
                type: "error",
                message: "Error removing the switch",
              })
            );
          }
          break;
      }
    } catch (err) {
      console.error("Error processing WebSocket message:", err);
    }
  });
});

// Handle WebSocket upgrade
server.on("upgrade", function (request, socket, head) {
  sessionParser(request, {}, () => {
    if (!request.session?.passport?.user) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }

    // Wichtig: Füge die Session-Informationen zur Request hinzu
    request.user = request.session.passport.user;

    wss.handleUpgrade(request, socket, head, function (ws) {
      wss.emit("connection", ws, request);
    });
  });
});

app.use(express.static("public"));

// Server starten
const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
  console.log(`Server running on port: ${PORT}`);

  try {
    // Start nur den FCM Listener
    await startFCMListener();
    console.log("FCM Listener started");
  } catch (error) {
    console.error("Error starting services:", error);
  }
});

// Cleanup function for server shutdown
function cleanup() {
  if (rustplusInstance) {
    try {
      rustplusInstance.disconnect();
      console.log("RustPlus connection disconnected");
    } catch (error) {
      console.error("Error disconnecting RustPlus connection:", error);
    }
    rustplusInstance = null;
    isConnected = false;
  }
}

// Add cleanup handling
process.on("SIGINT", () => {
  console.log("Server shutting down...");
  cleanup();
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log("Server shutting down...");
  cleanup();
  process.exit(0);
});

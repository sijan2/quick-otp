import { config } from "./lib/config"
import { oauthManager } from "./lib/oauth"

interface Message {
  action: string
  data: any
  timestamp: number
  retryCount?: number
}

let socket: WebSocket | null = null
let reconnectAttempts = 0
const MAX_RECONNECT_ATTEMPTS = 5
const RECONNECT_DELAY = 5000
const KEEP_ALIVE_INTERVAL = 30000
let authFailedTimestamp = 0
const AUTH_RETRY_COOLDOWN = 60000 // 1 minute cooldown between auth attempts
let manualAuthRequested = false // Flag to track if auth was manually requested
let intentionalDisconnect = false // New flag

let messageQueue: Message[] = []
const contentScriptReadyTabs = new Set<number>()
const MAX_RETRY_COUNT = 5

// User ID and WebSocket token
let userId: string | null = null
let wsToken: string | null = null
let tokenExpiry: number = 0

// Periodically check WebSocket connection (keep)
setInterval(async () => {
  try {
    const tokenResponse = await oauthManager.getTokenResponse(); // Get the raw token response first

    if (!tokenResponse || !tokenResponse.id_token) {
      // NO local token AT ALL. User is properly logged out.
      // The periodic check should NOT try to initiate a new login.
      console.log("Periodic check: No local token response. User is logged out. Waiting for manual login.");
      if (socket && socket.readyState === WebSocket.OPEN) { // If socket is somehow open, close it.
          console.warn("Periodic check: Closing WebSocket as user is logged out.");
          intentionalDisconnect = true;
          socket.close(1001, "User logged out, periodic check.");
          socket = null;
      }
      return; // Exit the periodic check for auth purposes
    }

    // Token response exists, now check if it's authenticated (not expired by more than 5 min buffer)
    // oauthManager.isAuthenticated() will internally use the tokenResponse again, which is fine.
    const isAuthenticated = await oauthManager.isAuthenticated(); 

    if (!isAuthenticated) {
      // Token exists but is expired/invalid. THIS is when we attempt refresh.
      console.log("Periodic check: User not authenticated or id_token expired/nearing expiry. Attempting to refresh id_token...");
      try {
        const newIdToken = await oauthManager.getIdToken(); // This will try backend refresh, then interactive
        if (newIdToken) {
          console.log("Periodic check: id_token refreshed successfully.");
          if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
            console.log("Periodic check: Closing existing WebSocket to reconnect with new token.");
            intentionalDisconnect = true; 
            socket.close(1000, "Reconnecting after id_token refresh");
            socket = null; 
          }
          console.log("Periodic check: Ensuring WebSocket is connected with new token.");
          connectWebSocket(); 
        } else {
          console.warn("Periodic check: id_token refresh attempt did not yield a new token. Auth may be lost.");
          if (socket && socket.readyState === WebSocket.OPEN) {
             console.warn("Periodic check: Closing WebSocket as authentication refresh failed.");
             intentionalDisconnect = true;
             socket.close(1008, "Authentication token expired and refresh failed");
             socket = null;
          }
        }
      } catch (refreshError: any) {
        console.error("Periodic check: Error during id_token refresh:", refreshError.message);
        if (socket && socket.readyState === WebSocket.OPEN) {
            console.warn("Periodic check: Closing WebSocket due to error in authentication refresh.");
            intentionalDisconnect = true;
            socket.close(1008, "Authentication token refresh error");
            socket = null;
        }
      }
    } else {
      // Authenticated and id_token is fine. Check WebSocket itself.
      if (!socket || socket.readyState === WebSocket.CLOSED || socket.readyState === WebSocket.CLOSING) {
        console.warn("Periodic check: WebSocket disconnected (while id_token is valid), attempting to reconnect...");
        connectWebSocket(); 
      }
    }
  } catch (authErr: any) { // Error from oauthManager.getTokenResponse() or .isAuthenticated() itself
    console.error("Error in periodic WS check (outer try-catch):", authErr.message);
  }
}, 60000); // Keep interval

function authenticateWithGoogle(forceAuth: boolean = false): void {
  const now = Date.now();
  if (!forceAuth && authFailedTimestamp > 0 && (now - authFailedTimestamp) < AUTH_RETRY_COOLDOWN) {
    console.log("Auth cooldown, skipping retry");
    return;
  }
  if (forceAuth) manualAuthRequested = true;

  oauthManager.getIdToken()
    .then(token => {
        if (token) {
            connectWebSocket(); 
        } else {
            console.warn("ID token not available after auth; WebSocket connection deferred.");
        }
    })
    .catch(error => {
      console.error("Failed to authenticate with Google:", error);
    });
}

function connectWebSocket(): void {
  if (socket?.readyState === WebSocket.OPEN || socket?.readyState === WebSocket.CONNECTING) return;

  oauthManager.getTokenResponse().then(tokenResponse => {
    if (!tokenResponse?.id_token) {
      console.warn("Cannot connect WebSocket: Google ID token not available.");
      return; 
    }
    const googleIdToken = tokenResponse.id_token;

    fetch(`${config.BACKEND_URL}/auth/ws-token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ idToken: googleIdToken })
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`Failed to get WebSocket token: ${response.status} ${response.statusText}`);
      }
      return response.json();
    })
    .then(wsTokenData => { 
      if (!wsTokenData || !wsTokenData.token || !wsTokenData.userId) {
          throw new Error("Invalid response from /auth/ws-token endpoint");
      }
      userId = wsTokenData.userId;
      wsToken = wsTokenData.token;

      if (typeof wsToken !== 'string') {
          console.error("WebSocket token is not a string after validation:", wsToken);
          throw new Error("WebSocket token is invalid after fetch.");
      }

      const wsUrl = `${config.WEBSOCKET_URL}/${userId}?token=${encodeURIComponent(wsToken!)}`;
      
      establishWebSocketConnection(wsUrl);
    })
    .catch(error => {
      console.error("Error getting WebSocket token or connecting:", error);
      userId = null;
      wsToken = null;
      handleReconnection();
    });

  }).catch(error => {
      console.error("Error getting Google token for WS connection:", error);
  });
}

function establishWebSocketConnection(wsUrl: string): void {
  try {
    socket = new WebSocket(wsUrl);
    intentionalDisconnect = false; // Reset flag on new connection attempt

    socket.onopen = (): void => {
      console.log("WebSocket connected successfully");
      reconnectAttempts = 0;
      startWebSocketPing();
    };

    socket.onmessage = async (event: MessageEvent): Promise<void> => {
      try {
        const serverMessage = JSON.parse(event.data);

        if (serverMessage.type === "OTP_RESULT" && serverMessage.payload) {
            const { code, url } = serverMessage.payload;
            if (url && !code) {
                console.log(`[WebSocket] Auto-opening received URL: ${url.substring(0, 50)}...`);
                openUrlInNewTab(url);
                return; 
            }
            queueMessage({ action: "otpResultReceived", data: { code: code || null, url: url || null, messageId: serverMessage.payload.messageId || null }, timestamp: Date.now() });

        } else if (serverMessage.type === "pong" || serverMessage.type === "PONG") {
            // console.log("[WebSocket] Received pong:", serverMessage); // Keep commented or enable for debug
        } else if (serverMessage.type === "CONNECTED") {
             // console.log("[WebSocket] Connection confirmed by server:", serverMessage.message); // Keep commented
        } else {
            console.warn("[WebSocket] Received unknown message type:", serverMessage.type, serverMessage.payload); // Log payload too for context
        }

      } catch (error) { console.error("[WebSocket] Error handling message:", error); }
    };

    socket.onerror = (error: Event): void => {
      console.error("WebSocket error:", error);
    };

    socket.onclose = (event: CloseEvent): void => {
      const reason = event.reason || 'No reason provided';
      console.warn(`WebSocket disconnected. Code: ${event.code}, Reason: ${reason.substring(0,100)}`);
      socket = null; 
      
      if (intentionalDisconnect) {
        console.log("WebSocket closed intentionally (e.g., due to logout). No reconnection attempt.");
        intentionalDisconnect = false; // Reset flag
      } else {
        handleReconnection(); // Attempt to reconnect only if not intentional
      }
    };
  } catch (error) { console.error("Error creating WebSocket:", error); handleReconnection(); }
}

function handleReconnection(): void {
  if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
    const delay = RECONNECT_DELAY * Math.pow(2, reconnectAttempts);
    reconnectAttempts++;
    console.warn(`Reconnecting WebSocket in ${delay / 1000} seconds... (Attempt ${reconnectAttempts})`);
    setTimeout(connectWebSocket, delay);
  } else { console.error("Max WebSocket reconnection attempts reached."); }
}

function queueMessage(message: Message): void {
  message.timestamp = Date.now()
  messageQueue.push(message)
  processMessageQueue()
}

function processMessageQueue(): void {
  if (contentScriptReadyTabs.size === 0) {
    console.log("No content scripts are ready. Notifying user.")
    while (messageQueue.length > 0) {
      const message = messageQueue.shift()
      if (message) {
        handleMessageWithoutContentScript(message)
      }
    }
    return
  }

  while (messageQueue.length > 0) {
    const message = messageQueue.shift()
    if (message) {
      sendMessageToContentScript(message)
    }
  }
}

function handleMessageWithoutContentScript(message: Message): void {
  if (message.action === "otpResultReceived" && message.data) {
    const { code, url } = message.data;
    
    let notificationTitle = "Verification Info Received";
    let notificationMessage = "";
    let notificationUrlToOpen: string | null = null;

    if (url) {
        notificationTitle = "Verification Link Received";
        notificationMessage = `Click to open the verification link.`;
        try {
            const cleanUrl = new URL(url).toString();
            notificationUrlToOpen = cleanUrl;
            notificationMessage += `\nURL: ${cleanUrl.substring(0, 50)}...`;
        } catch (e) {
            console.error("Received invalid URL in otpResultReceived:", url, e);
            notificationMessage = "Received an invalid URL.";
        }
    } else if (code) {
        notificationTitle = "OTP Code Received";
        notificationMessage = `Code: ${code}`;
    } else {
        notificationTitle = "Notification Received";
        notificationMessage = "Received a notification from the server.";
        console.log("[Notification] Received OTP_RESULT with no code or URL.", message.data);
    }
    
    showChromeNotification(
      notificationTitle,
      notificationMessage,
      notificationUrlToOpen 
        ? () => { 
            console.log("Notification clicked, opening URL:", notificationUrlToOpen);
            openUrlInNewTab(notificationUrlToOpen!);
          } 
        : undefined
    );
  } else {
      console.warn("Handling unknown message action without content script:", message.action);
      showChromeNotification("Quick OTP Notification", `Received an update: ${JSON.stringify(message.data).substring(0, 100)}`);
  }
}

function sendMessageToContentScript(message: Message): void {
  if (contentScriptReadyTabs.size === 0) {
    console.log("No content script tabs available, handling message without content script")
    handleMessageWithoutContentScript(message)
    return
  }
  
  let deliveredToAnyTab = false
  
  const tabsToProcess = Array.from(contentScriptReadyTabs)
  
  tabsToProcess.forEach((tabId) => {
    try {
      chrome.tabs.sendMessage(
        tabId, 
        message, 
        (response) => {
          if (chrome.runtime.lastError) {
            console.error(
              `Error sending message to tab ${tabId}:`,
              chrome.runtime.lastError.message
            )
            contentScriptReadyTabs.delete(tabId)
            
            if (contentScriptReadyTabs.size === 0 && !deliveredToAnyTab) {
              message.retryCount = (message.retryCount || 0) + 1
              if (message.retryCount < MAX_RETRY_COUNT) {
                messageQueue.unshift(message)
                setTimeout(processMessageQueue, 1000)
              } else {
                console.error("Max retry attempts reached for message:", message)
                handleMessageWithoutContentScript(message)
              }
            }
          } else {
            deliveredToAnyTab = true
          }
        }
      )
    } catch (error) {
      console.error(`Error sending message to tab ${tabId}:`, error)
      contentScriptReadyTabs.delete(tabId)
    }
  })
}

function showChromeNotification(
  title: string,
  message: string,
  callback?: () => void
): void {
  const notificationId = "verification_" + Date.now()
  chrome.notifications.create(notificationId, {
    type: "basic",
    iconUrl: "/icons/icon48.png",
    title: title,
    message: message,
    priority: 2,
    requireInteraction: true,
  })

  if (callback) {
    chrome.notifications.onClicked.addListener(function listener(clickedId) {
      if (clickedId === notificationId) {
        callback()
        chrome.notifications.onClicked.removeListener(listener)
      }
    })
  }
}

function openUrlInNewTab(url: string): void {
  if (!url) { console.error("Attempted to open null/empty URL"); return; }
  console.log("Opening URL in new tab (first 50 chars):", url.substring(0,50));
  
  try {
    chrome.tabs.create({ 
      url: url,
      active: true
    }, (tab) => {
      if (chrome.runtime.lastError) {
        console.error("Tab creation error:", chrome.runtime.lastError.message);
        
        tryFallbackUrlOpening(url);
      } else if (tab) {
        console.log("Successfully opened URL in tab:", tab.id);
      }
    });
  } catch (error) {
    console.error("Exception when creating tab:", error);
    tryFallbackUrlOpening(url);
  }
}

function tryFallbackUrlOpening(url: string): void {
  console.log("Using fallback URL opening methods for:", url);
  
  try {
    const cleanURL = new URL(url);
    const urlString = cleanURL.toString();
    console.log("Cleaned URL for fallback attempt:", urlString);
    
    chrome.tabs.create({ url: urlString }, (tab) => {
      if (chrome.runtime.lastError) {
        console.error("First fallback failed:", chrome.runtime.lastError.message);
        secondFallback(url);
      }
    });
  } catch (error) {
    console.error("URL cleaning failed:", error);
    secondFallback(url);
  }
}

function secondFallback(url: string): void {
  console.log("Attempting window creation as second fallback");
  
  try {
    chrome.windows.create({ 
      url: url,
      type: 'normal',
      focused: true
    }, (window) => {
      if (chrome.runtime.lastError) {
        console.error("Window creation failed:", chrome.runtime.lastError.message);
        
        finalFallback(url);
      }
    });
  } catch (error) {
    console.error("Window creation exception:", error);
    finalFallback(url);
  }
}

function finalFallback(url: string): void {
  console.log("Final fallback: Attempting to open in current window via chrome.tabs.query");
  
  chrome.tabs.query({active: true, lastFocusedWindow: true}, (tabs) => {
    if (chrome.runtime.lastError) {
      console.error("Final fallback failed:", chrome.runtime.lastError.message);
      return;
    }
    
    if (tabs && tabs[0] && tabs[0].id) {
      console.log("Opening URL in current tab as last resort");
      
      chrome.tabs.create({
        url: url,
        active: true,
        index: tabs[0].index + 1
      });
    }
  });
}

function keepAlive(): void {
  if (socket?.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: "ping" }))
  }
}

let pingIntervalId: ReturnType<typeof setInterval> | null = null;

function startWebSocketPing(): void {
  pingIntervalId = setInterval(() => {
    if (socket?.readyState === WebSocket.OPEN) {
      try { socket.send(JSON.stringify({ type: "ping", timestamp: Date.now() })); }
      catch (error) { console.error("Error sending ping:", error); }
    } else {
      if (!socket || socket.readyState === WebSocket.CLOSED) { connectWebSocket(); }
    }
  }, KEEP_ALIVE_INTERVAL);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "contentScriptReady") {
    if (sender.tab?.id != null) {
      contentScriptReadyTabs.add(sender.tab.id);
      processMessageQueue();
      sendResponse({ status: "Background acknowledged readiness" });
    } else {
        sendResponse({ status: "Background received readiness, but no tab ID?" });
    }
    return true;
  } else if (message.action === "loginManually") {
    authenticateWithGoogle(true);
    sendResponse({ success: true, message: "Login process started" });
    return true;
  } else if (message.action === "getAuthStatus") {
    oauthManager.isAuthenticated().then(isAuthenticated => {
        if (isAuthenticated) {
             oauthManager.getTokenResponse().then(tokenResponse => {
                let email = "Unknown";
                if (tokenResponse?.id_token) {
                    try {
                        const payload = tokenResponse.id_token.split(".")[1];
                        const decoded = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
                        email = decoded.email || email;
                    } catch(e) { console.warn("Failed to parse ID token for email in getAuthStatus", e); }
                }
                sendResponse({ isAuthenticated: true, email: email });
            });
        } else {
            sendResponse({ isAuthenticated: false, lastFailedTimestamp: authFailedTimestamp });
        }
    }).catch(error => {
        console.error("Error checking auth status:", error);
        sendResponse({ isAuthenticated: false, error: error.message });
    });
    return true;
  } else if (message.action === "explicitWsClose") {
    console.log("[Background] Explicit WebSocket close requested due to logout.");
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      console.log("[Background] Closing active WebSocket connection intentionally.");
      intentionalDisconnect = true; // Set flag BEFORE closing
      socket.close(1000, "User logged out"); 
      socket = null; 
      if (pingIntervalId) {
        clearInterval(pingIntervalId);
        pingIntervalId = null;
      }
      sendResponse({ status: "WebSocket close initiated" });
    } else {
      console.log("[Background] No active WebSocket to close or already closing/closed.");
      sendResponse({ status: "No active WebSocket to close" });
    }
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
  if (contentScriptReadyTabs.has(tabId)) {
    contentScriptReadyTabs.delete(tabId)
  }
})

function getWebSocketStateString(state: number): string {
  switch (state) {
    case WebSocket.CONNECTING: return "CONNECTING (0)"
    case WebSocket.OPEN: return "OPEN (1)"
    case WebSocket.CLOSING: return "CLOSING (2)"
    case WebSocket.CLOSED: return "CLOSED (3)"
    default: return `UNKNOWN (${state})`
  }
}

// Tab updated listener (keep)
chrome.tabs.onUpdated.addListener(
  async ( // Make the listener async to use await for the promise if needed, though not strictly necessary for just .catch
    tabId: number,
    changeInfo: chrome.tabs.TabChangeInfo,
    tab: chrome.tabs.Tab
  ) => {
    if (changeInfo.status === "complete") {
      // console.log(`Tab ${tabId} updated, status complete. Sending checkContentScriptReady.`); // Optional: for debugging if needed
      chrome.tabs.sendMessage(tabId, { action: "checkContentScriptReady" })
        .then(response => {
          // Optional: log response if content script replies, e.g., response.status
          // if (response && response.status) {
          //   console.log(`Content script in tab ${tabId} responded to check: ${response.status}`);
          // }
        })
        .catch(error => {
          // Gracefully handle the common "no receiving end" error
          if (error.message === "Could not establish connection. Receiving end does not exist." || 
              error.message?.includes("Receiving end does not exist")) {
            // This is expected for tabs where the content script isn't injected or isn't ready.
            // console.warn(`Failed to send checkContentScriptReady to tab ${tabId} (likely no content script): ${error.message}`);
          } else {
            // Log other unexpected errors
            console.error(`Error sending checkContentScriptReady to tab ${tabId}:`, error);
          }
        });
    }
    // Removed the OAuth callback URL log as it's not directly related to this error
  }
)

async function initializeConnectionOnStartup() {
  console.log("[Startup] Checking initial authentication state...");
  try {
    const isAuthenticated = await oauthManager.isAuthenticated();
    if (isAuthenticated) {
      console.log("[Startup] User is already authenticated. Initiating WebSocket connection...");
      connectWebSocket(); // Connect WebSocket if already authenticated
    } else {
      console.log("[Startup] User is not authenticated. Attempting to refresh session immediately...");
      // Attempt to get/refresh the ID token.
      // getIdToken will try backend refresh first, then interactive if necessary.
      const newIdToken = await oauthManager.getIdToken();
      if (newIdToken) {
        console.log("[Startup] Session refreshed successfully. Initiating WebSocket connection...");
        connectWebSocket(); // Connect WebSocket after successful refresh
      } else {
        console.log("[Startup] Session could not be refreshed automatically. Waiting for manual login or periodic check.");
      }
    }
  } catch (error: any) { 
    console.error("[Startup] Error during initial authentication/refresh attempt:", error.message);
  }
}

initializeConnectionOnStartup();
console.log("Quick OTP Background Service Worker Loaded.");

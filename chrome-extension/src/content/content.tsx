import ReactDOM from "react-dom/client"
import ContentApp from "./ContentApp"

let root: ReactDOM.Root | null = null

let isAppInjected = false

function injectApp() {
  if (!isAppInjected) {
    const rootDiv = document.createElement("div")
    rootDiv.id = "extension-root"
    document.body.appendChild(rootDiv)
    root = ReactDOM.createRoot(rootDiv)
    isAppInjected = true
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // console.log("Content script received message:", message); // Can be removed
  
  if (message.action === "otpDetected") { // Old action
    console.warn("Received obsolete action: otpDetected");
    const otpCode = message.data.code;
    if (otpCode) {
        if (!root) injectApp();
        // console.log("Rendering ContentApp with OTP code (from otpDetected):", otpCode);
        root?.render(<ContentApp otp={otpCode} />);
        sendResponse({ status: "OTP displayed (obsolete action)" });
    } else { sendResponse({ status: "No OTP in obsolete action" }); }

  } else if (message.action === "otpResultReceived") {
    // console.log("OTP Result received:", message.data);
    const otpCode = message.data.code;
    const otpUrl = message.data.url;

    if (otpCode) {
        if (!root) injectApp();
        // console.log("Rendering ContentApp with OTP code:", otpCode, "and URL:", otpUrl);
        root?.render(<ContentApp otp={otpCode} url={otpUrl} />); 
        sendResponse({ status: "OTP displayed" + (otpUrl ? " with URL option" : "") });
    } else if (otpUrl) {
        console.warn("URL received, content script not displaying it."); // Keep this warn
        sendResponse({ status: "URL received, not displayed by content" });
    } else {
        console.warn("otpResultReceived without code or URL."); // Keep this warn
        sendResponse({ status: "No code/URL received" });
    }
  } 
  // ... (other old handlers can be removed if truly obsolete, or keep their warns)
})

// Inform background script that content script is ready (initial load)
// console.log("Content script loaded, sending initial contentScriptReady message")
// chrome.runtime.sendMessage({ action: "contentScriptReady" }) // This might be redundant if checkContentScriptReady is used
// Let's ensure readiness is signaled reliably.
// A common pattern is to only send readiness *after* the listener is attached.
function signalReadiness() {
    // console.log("Content script signaling readiness.");
    chrome.runtime.sendMessage({ action: "contentScriptReady" }, (response) => {
        if (chrome.runtime.lastError) {
            console.warn("Could not send readiness message to background:", chrome.runtime.lastError.message); // Keep
        }
    });
}

// Use a small delay or check document state before signaling readiness
if (document.readyState === "complete") {
  signalReadiness()
} else {
  window.addEventListener("load", signalReadiness)
}

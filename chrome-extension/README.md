# Quick OTP - Chrome Extension Setup Guide

This Chrome Extension works with the Quick OTP backend to provide users with their OTPs (One-Time Passwords) and verification links by processing their emails.

## Prerequisites

1.  **Node.js and pnpm:** Ensure you have Node.js (preferably LTS version) and pnpm installed.
    *   Node.js: [https://nodejs.org/](https://nodejs.org/)
    *   pnpm: `npm install -g pnpm`
2.  **Running Backend:** The Quick OTP backend Cloudflare Worker must be set up, deployed, and accessible. You will need its base URL and WebSocket URL.
3.  **Google Chrome or Chromium-based Browser:** To install and test the extension.

## Setup & Build Steps

1.  **Clone the Repository (if not already done):**
    ```bash
    git clone https://github.com/sijan2/quick-otp.git
    cd quick-otp/chrome-extension
    ```

2.  **Install Dependencies:**
    ```bash
    pnpm install
    ```

3.  **Configure Environment Variables:**
    The extension needs to know the URLs of your deployed backend. This is typically handled by creating a `.env` file in the `chrome-extension` directory.

    Create a file named `.env` in the `chrome-extension` root with the following content, replacing the placeholder URLs with your actual backend URLs:
    ```env
    EXTENSION_PUBLIC_BACKEND_URL=https://your-worker-app-name.your-cf-subdomain.workers.dev
    EXTENSION_PUBLIC_WEBSOCKET_URL=wss://your-worker-app-name.your-cf-subdomain.workers.dev
    ```
    *   `EXTENSION_PUBLIC_BACKEND_URL`: The base HTTP URL for your Cloudflare Worker backend (e.g., for `/auth/login`, `/api/...` endpoints).
    *   `EXTENSION_PUBLIC_WEBSOCKET_URL`: The WebSocket URL for your Cloudflare Worker (usually the same hostname as `BACKEND_URL` but with `wss://` and potentially a different path if configured, though your current setup uses the root for WebSocket upgrades via path routing).


4.  **Build the Extension:**
    *   **For Development (with hot reloading):**
        ```bash
        pnpm run dev
        ```
        This will typically build the extension into a `dist` folder and start a development server.
    *   **For Production Build:**
        ```bash
        pnpm run build
        ```
        This creates an optimized build in the `dist` folder, ready for packaging or loading into Chrome.

## Loading the Extension in Chrome

1.  Open Google Chrome.
2.  Navigate to `chrome://extensions`.
3.  Enable **Developer mode** (usually a toggle in the top right corner).
4.  Click on **"Load unpacked"**.
5.  Select the `chrome-extension/dist` folder from your project.
6.  The Quick OTP extension should now appear in your list of extensions and be active.

## Development Notes

*   **Hot Reloading:** When running `pnpm run dev`, changes to your source code should automatically rebuild the extension and reload it in the browser (if it's already loaded as unpacked).
*   **Service Worker & Popup Debugging:** You can inspect the service worker (background script) and popup console logs through the `chrome://extensions` page (click "Service worker" for the background script, and right-click -> Inspect on the popup UI).
*   **Content Script Debugging:** Content scripts run in the context of web pages. You can debug them using the Developer Tools (F12 or Ctrl+Shift+I) on any page where the content script is active.

## Key Files & Structure

*   `manifest.json`: Defines the extension's permissions, components, and metadata.
*   `src/background.ts`: The extension's service worker, handling core logic, WebSocket communication, and event management.
*   `src/popup/`: Contains the React components and logic for the extension's popup UI.
*   `src/content/`: Contains scripts injected into web pages (e.g., for displaying OTPs directly on a page).
*   `src/lib/`: Shared utility modules (e.g., `oauth.ts`, `config.ts`, `setup.ts`).
*   `dist/`: The output directory for the built extension (this is what you load into Chrome). 
# Quick OTP - Backend Setup Guide

This backend is a Cloudflare Worker that handles Google OAuth, manages Gmail API interactions (labels, filters, push notifications via Pub/Sub), and provides a WebSocket server for real-time communication with the Quick OTP Chrome Extension.

## Prerequisites

1.  **Node.js and pnpm:** Ensure you have Node.js (preferably LTS version) and pnpm installed.
    *   Node.js: [https://nodejs.org/](https://nodejs.org/)
    *   pnpm: `npm install -g pnpm`
2.  **Cloudflare Account:** You'll need a Cloudflare account.
3.  **Wrangler CLI:** Install or update the Wrangler CLI: `pnpm install -g wrangler` (or `npm install -g wrangler`). Then log in: `wrangler login`.
4.  **Google Cloud Platform (GCP) Project:**
    *   Create a GCP project.
    *   Enable the **Gmail API** and the **Google Cloud Pub/Sub API**.
    *   Create OAuth 2.0 Credentials (for a "Web application") to get a **Client ID** and **Client Secret**.
        *   Add Authorized JavaScript origins (e.g., `https://quiet-lab-240a.your-subdomain.workers.dev` - replace with your worker URL once deployed for testing, though not strictly necessary for the backend-only flow if redirect URI is properly set for worker).
        *   Add an Authorized redirect URI: This **must** match the `GOOGLE_REDIRECT_URI` you will set later (e.g., `https://your-worker-subdomain.workers.dev/auth/callback`).
    *   Create a Pub/Sub Topic (e.g., `otp-notifications`). Note its full topic name (e.g., `projects/your-gcp-project-id/topics/your-topic-name`).
    *   Create a Pub/Sub Subscription for this topic:
        *   **Delivery type:** Push
        *   **Endpoint URL:** This will be your deployed Worker's `/pubsub` endpoint (e.g., `https://your-worker-subdomain.workers.dev/pubsub`). You might need to deploy the worker first to get this URL, then come back and set it.
        *   **Enable authentication:** Select "Enable authentication". For the "Audience" field, use the same URL as your push endpoint (this will be your `GOOGLE_PUBSUB_JWT_AUDIENCE`). The service account should typically be `service-{PROJECT_NUMBER}@gcp-sa-pubsub.iam.gserviceaccount.com`. Ensure this service account has the "Pub/Sub Subscriber" (or more broadly, "Pub/Sub Editor") role and the "Service Account Token Creator" role on your project, or at least the permission to publish to the push endpoint.
5.  **OpenAI Account:**
    *   Obtain an OpenAI API Key for AI email processing.

## Setup Steps

1.  **Clone the Repository:**
    ```bash
    git clone git clone https://github.com/sijan2/quick-otp.git
    cd quick-otp/backend
    ```

2.  **Install Dependencies:**
    ```bash
    pnpm install
    ```

3.  **Configure Wrangler Secrets:**
    These are essential for your application to function. Run these commands in your `backend` directory and provide the values when prompted:

    *   **Google OAuth Credentials (from GCP):**
        ```bash
        pnpm wrangler secret put GOOGLE_CLIENT_ID
        pnpm wrangler secret put GOOGLE_CLIENT_SECRET
        ```

    *   **Application URLs & Identifiers (replace placeholders with your actual values):**
        ```bash
        # Your Worker's OAuth callback (must match GCP config)
        pnpm wrangler secret put GOOGLE_REDIRECT_URI
        # e.g., https://your-app-name.your-cf-subdomain.workers.dev/auth/callback

        # Your Worker's Pub/Sub push endpoint URL (must match GCP Pub/Sub subscription config)
        pnpm wrangler secret put GOOGLE_PUBSUB_JWT_AUDIENCE
        # e.g., https://your-app-name.your-cf-subdomain.workers.dev/pubsub

        # Full Pub/Sub topic name (from GCP)
        pnpm wrangler secret put PUBSUB_TOPIC_NAME
        # e.g., projects/your-gcp-project-id/topics/your-chosen-topic-name
        ```

    *   **Token Encryption Key (generate a strong random string, e.g., 32+ characters):**
        ```bash
		 # Generate a 32-character random string
        openssl rand -base64 24
        pnpm wrangler secret put TOKEN_ENCRYPTION_KEY
        ```

    *   **OpenAI API Key:**
        ```bash
        pnpm wrangler secret put OPENAI_API_KEY
        ```
        *(Optional) You can also set `OPENAI_MODEL_NAME` and `OPENAI_ENDPOINT` as secrets if you want to override defaults for the AI service.*

4.  **Update `wrangler.jsonc` (if necessary):
    *   **Worker Name:** Change the `"name"` field in `wrangler.jsonc` if you want a different name for your deployed worker (e.g., from `"quiet-lab-240a"` to your preferred name). This will affect your worker's URL.
    *   Verify `"main"` points to `"src/index.ts"`.
    *   The `durable_objects` bindings and `migrations` should generally be kept as they define the structure of your application's stateful components.

5.  **Deploy to Cloudflare Workers:**
    ```bash
    pnpm wrangler deploy
    ```
    After the first deployment, you will get your worker's URL (e.g., `https://your-app-name.your-cf-subdomain.workers.dev`). You may need to update your GCP Pub/Sub subscription's push endpoint URL and your GCP OAuth Client's Authorized Redirect URI with this URL if you didn't know it beforehand.

## Development

*   To run a local development server (simulates the Cloudflare environment):
    ```bash
    pnpm wrangler dev
    ```
*   This will typically run on `http://localhost:8787`.
*   **Note:** For local development, Pub/Sub push notifications from Google Cloud will not reach your local server unless you use a tunneling service (e.g., ngrok, cloudflared tunnel) and update your Pub/Sub subscription endpoint accordingly. OAuth might also require careful configuration of redirect URIs for localhost.

## Project Structure Key Files

*   `src/index.ts`: Main entry point for the Worker, handles HTTP routing.
*   `src/services/`: Contains business logic for Gmail, Auth, AI, Pub/Sub.
*   `src/durable-objects/`: Definitions for Durable Objects (`TokenStoreDO`, `WebSocketHubDO`).
*   `wrangler.jsonc`: Configuration file for Wrangler and Cloudflare Worker deployment.
*   `package.json`: Project dependencies and scripts.

## Important Notes

*   **Gmail API Scopes:** The application requests necessary scopes for reading emails, managing labels, filters, and basic settings. Users will be prompted for consent.
*   **Security:** Ensure all secrets are managed via `wrangler secret put` and are not hardcoded or committed to version control.
*   **Pub/Sub JWT Validation:** The JWT validation for incoming Pub/Sub messages in `src/index.ts` (`/pubsub` route) is crucial for production security and should be enabled.

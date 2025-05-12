# Quick OTP - Backend Setup

Cloudflare Worker backend for Google OAuth, Gmail API interaction, and WebSocket communication with the Quick OTP Chrome Extension.

## Prerequisites

1.  **Node.js & pnpm:** Install [Node.js (LTS)](https://nodejs.org/) and [pnpm](https://pnpm.io/installation#using-npm).
2.  **Cloudflare Account & Wrangler CLI:**
    *   Sign up for a [Cloudflare account](https://dash.cloudflare.com/sign-up).
    *   Install Wrangler CLI: `pnpm install -g wrangler` (or `npm`).
    *   Login: `wrangler login`.
3.  **Google Cloud Platform (GCP) Project:**
    *   Create a GCP project.
    *   Enable **Gmail API** and **Google Cloud Pub/Sub API**.
    *   **OAuth 2.0 Credentials (Web application):**
        *   Note Client ID & Client Secret.
        *   Authorized redirect URI: `https://<YOUR_WORKER_URL>/auth/callback` (update after first deploy).
    *   **Pub/Sub Topic:**
        *   Create a topic (e.g., `otp-notifications`). Note its full name: `projects/<GCP_PROJECT_ID>/topics/<YOUR_TOPIC_NAME>`.
    *   **Pub/Sub Subscription (for the topic):**
        *   Delivery type: **Push**.
        *   Endpoint URL: `https://<YOUR_WORKER_URL>/pubsub` (update after first deploy).
        *   Authentication: **Enable**.
            *   Audience: Use the push endpoint URL (e.g., `https://<YOUR_WORKER_URL>/pubsub`).
            *   Service Account: `service-{PROJECT_NUMBER}@gcp-sa-pubsub.iam.gserviceaccount.com`.
            *   Ensure this service account has "Pub/Sub Subscriber" and "Service Account Token Creator" roles.
4.  **(Optional) OpenAI Account & API Key:** For AI email processing if using OpenAI.
5.  **(Optional) Google API Key:** If using Gemini, a Google API key is needed.

## Setup

1.  **Clone & Install:**
    ```bash
    git clone https://github.com/sijan2/quick-otp.git
    cd quick-otp/backend
    pnpm install
    ```

2.  **Configure Wrangler Secrets:**
    In the `backend` directory, run `pnpm wrangler secret put <SECRET_NAME>` for each of the following and provide the values when prompted:

    *   **`AI_PROVIDER`**: Set to either `"openai"` or `"gemini"` to choose the AI service.
    *   **`GOOGLE_API_KEY`**: Your Google API Key (used if `AI_PROVIDER` is `"gemini"` or for other Google services not covered by OAuth).
    *   **`GOOGLE_CLIENT_ID`**: Your Google OAuth Client ID (from GCP).
    *   **`GOOGLE_CLIENT_SECRET`**: Your Google OAuth Client Secret (from GCP).
    *   **`GOOGLE_PUBSUB_JWT_AUDIENCE`**: Your Worker's Pub/Sub push endpoint URL (e.g., `https://<WORKER_NAME>.<YOUR_CF_USER>.workers.dev/pubsub`). Must match GCP Pub/Sub subscription config.
    *   **`GOOGLE_REDIRECT_URI`**: Your Worker's OAuth callback URL (e.g., `https://<WORKER_NAME>.<YOUR_CF_USER>.workers.dev/auth/callback`). Must match GCP OAuth config.
    *   **`OPENAI_API_KEY`**: Your OpenAI API Key (required if `AI_PROVIDER` is `"openai"`).
    *   **`PUBSUB_TOPIC_NAME`**: Full Pub/Sub topic name from GCP (e.g., `projects/<GCP_PROJECT_ID>/topics/<YOUR_TOPIC_NAME>`).
    *   **`TOKEN_ENCRYPTION_KEY`**: A strong random string for encrypting tokens. Generate one with:
        ```bash
        openssl rand -base64 24
        ```
    *   **`WEBSOCKET_JWT_SECRET`**: A strong random string for signing WebSocket JWTs. Generate one similarly:
        ```bash
        openssl rand -base64 24
        ```

    *   **(Optional) OpenAI Model/Endpoint Overrides (if `AI_PROVIDER="openai"`):**
        *   `pnpm wrangler secret put OPENAI_MODEL_NAME`
        *   `pnpm wrangler secret put OPENAI_ENDPOINT`

    *   **(Optional) Gemini Model/Endpoint Overrides (if `AI_PROVIDER="gemini"`):**
        *   `pnpm wrangler secret put GEMINI_MODEL_NAME`
        *   `pnpm wrangler secret put GEMINI_ENDPOINT`
        *   *(Note: `GOOGLE_API_KEY` is used for Gemini authentication).*


3.  **Configure `wrangler.jsonc`:**
    *   Update `"name"` to your desired worker name (this affects the URL).
    *   Ensure `"main"` is `"src/index.ts"`.
    *   Keep `durable_objects` bindings and `migrations` as is.

4.  **Deploy:**
    ```bash
    pnpm wrangler deploy
    ```
    *   Note the deployed worker URL. Update GCP redirect URI and Pub/Sub push endpoint if necessary.

## Development

*   Local dev server: `pnpm wrangler dev` (runs on `http://localhost:8787`).
*   **Note:** Pub/Sub push won't reach localhost without tunneling (e.g., ngrok, cloudflared tunnel) and updated GCP subscription settings.

## Key Files

*   `src/index.ts`: Main router & entry point.
*   `src/services/`: Business logic (Auth, Gmail, AI, Pub/Sub).
*   `src/durable-objects/`: Durable Object definitions.
*   `wrangler.jsonc`: Worker deployment configuration.

## Security

*   Use `wrangler secret put` for all sensitive credentials.
*   **Enable and verify Pub/Sub JWT validation in `src/index.ts` for production.**
*   Review requested Gmail API scopes for least privilege.

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
          ![Redacted Image Blurring Tool](https://github.com/user-attachments/assets/cf461f53-b10d-4d17-9100-05b47b77f149)

          
    *   **Pub/Sub Topic:**
        *   Create a topic (e.g., `otp-notifications`). Note its full name: `projects/<GCP_PROJECT_ID>/topics/<YOUR_TOPIC_NAME>`.
    *   **Pub/Sub Subscription (for the topic):**
        *   Delivery type: **Push**.
        *   Endpoint URL: `https://<YOUR_WORKER_URL>/pubsub` (update after first deploy).
        *   Authentication: **Enable**.
            *   Audience: Use the push endpoint URL (e.g., `https://<YOUR_WORKER_URL>/pubsub`).
            *   Service Account: `service-{PROJECT_NUMBER}@gcp-sa-pubsub.iam.gserviceaccount.com`.
            *   Ensure this service account has "Pub/Sub Subscriber" and "Service Account Token Creator" roles.
         
![Redacted Image Blurring Tool (1)](https://github.com/user-attachments/assets/d917cb94-57a1-4bb9-a1db-573f3778657a)
      
4.   OpenAI Account & API Key:** For AI email processing if using OpenAI.
5.   Google API Key:** If using Gemini, a Google API key is needed.

## Setup

1.  **Clone & Install:**
    ```bash
    git clone https://github.com/sijan2/quick-otp.git
    cd quick-otp/backend
    pnpm install
    ```

2.  **Configure Wrangler Secrets:**
    In the `backend` directory, run `pnpm wrangler secret put <SECRET_NAME>` for each of the following and provide the values when prompted:
    <img width="754" alt="94255d1b942e6ac4ebe3795690c8f886e2435d096aad8a9cc671834262248933" src="https://github.com/user-attachments/assets/a320b203-a21d-42b8-9666-8b1f35723021" />

	 *   **`AI_PROVIDER`**: Set to either `"openai"` or `"gemini"` to choose the AI service.

	 *   **`GOOGLE_PUBSUB_JWT_AUDIENCE`**: Your Worker's Pub/Sub push endpoint URL (e.g., `https://<WORKER_NAME>.<YOUR_CF_USER>.workers.dev/pubsub`). Must match GCP Pub/Sub subscription config.

    *   **`TOKEN_ENCRYPTION_KEY`**: A strong random string for encrypting tokens. Generate one with:
        ```bash
        openssl rand -hex 32
        ```
    *   **`WEBSOCKET_JWT_SECRET`**: A strong random string for signing WebSocket JWTs. Generate one similarly:
        ```bash
        openssl rand -hex 32
        ```
        


4.  **Configure `wrangler.jsonc`:**
    *   Update `"name"` to your desired worker name (this affects the URL).
    *   Ensure `"main"` is `"src/index.ts"`.
    *   Keep `durable_objects` bindings and `migrations` as is.

5.  **Deploy:**
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

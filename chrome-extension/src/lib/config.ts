
export const config = {
  // URL for establishing WebSocket connection (e.g., wss://your-worker.your-domain.workers.dev)
  WEBSOCKET_URL: process.env.EXTENSION_PUBLIC_WEBSOCKET_URL || '',

  // Base URL for backend HTTP endpoints (e.g., https://your-worker.your-domain.workers.dev)
  BACKEND_URL: process.env.EXTENSION_PUBLIC_BACKEND_URL || '',

 
};

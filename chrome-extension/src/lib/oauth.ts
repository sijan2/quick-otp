import { config } from "./config"
import { Storage } from "./storage"

interface TokenResponse {
  access_token: string
  refresh_token?: string
  expires_in: number
  token_type: string
  scope: string
  id_token?: string
  expiryTimestamp: number
  email?: string // Add email field for our custom uses
}

class OAuthManager {
  // Required scopes for your use case
  // Include OpenID scopes so Google returns an ID token (needed for backend registration & WebSocket auth)
  private static readonly SCOPES = [
    "openid",
    "email",
    "profile",
    "https://mail.google.com/",
  ]
  
  private storage: Storage
  private authInProgress: boolean = false
  private authPromise: Promise<string> | null = null // This promise will now resolve with id_token

  constructor() {
    this.storage = new Storage()
  }

  /**
   * Ensures the user is authenticated and returns a valid ID token.
   * If no token found or it's expired, initiates the login flow.
   */
  public async getIdToken(): Promise<string> { // Renamed, returns id_token
    try {
      // If authentication is already in progress, return the existing promise
      if (this.authInProgress && this.authPromise) {
        // console.log("Auth already in progress, waiting for id_token...");
        return this.authPromise;
      }

      // console.log("Getting ID token...");
      const tokenResponse = await this.getTokenResponse();

      if (!tokenResponse || !tokenResponse.id_token) { // Also check if id_token exists
        // console.log("No stored token or id_token, initiating login flow...");
        this.authInProgress = true;
        this.authPromise = this.loginWithLock(); // loginWithLock now returns id_token
        return this.authPromise; 
      } else if (this.isTokenExpired(tokenResponse)) {
        // console.log("Stored token expired, initiating new login flow...");
        this.authInProgress = true;
        this.authPromise = this.loginWithLock(); // loginWithLock now returns id_token
        return this.authPromise;
      }
      // console.log("Using existing valid id_token.");
      // Return the valid id_token
      return tokenResponse.id_token; 
    } catch (error) {
      console.error("Error in getIdToken:", error);
      this.authInProgress = false;
      this.authPromise = null;
      throw error;
    }
  }

  /**
   * Wrapper around login that ensures only one login flow can happen at a time.
   * Returns the ID token upon successful login.
   */
  private async loginWithLock(): Promise<string> { // Returns id_token
    try {
      const tokenResponse = await this.login()
      if (!tokenResponse.id_token) { // Should always have id_token after successful login
        throw new Error("Login completed but id_token was missing.");
      }
      return tokenResponse.id_token // Return the id_token
    } finally {
      // Reset auth status when done regardless of success or failure
      this.authInProgress = false
      this.authPromise = null
    }
  }

  /**
   * Uses launchWebAuthFlow to trigger the backend OAuth flow 
   * and parse the id_token from the final redirect URL.
   */
  private async launchWebAuthFlow(): Promise<{ id_token: string }> { // Returns object with id_token
    // Construct the URL to your backend's login endpoint
    // It needs to know where to redirect back to the extension
    const backendLoginUrl = new URL(config.BACKEND_URL + '/auth/login');
    const extensionCallbackUrl = `https://${chrome.runtime.id}.chromiumapp.org`; // Default callback for extensions
    backendLoginUrl.searchParams.set('redirectUrl', extensionCallbackUrl);

    // console.log(`[OAuth] Starting auth flow via backend: ${backendLoginUrl.toString()}`);

    return new Promise<{ id_token: string }>((resolve, reject) => {
      chrome.identity.launchWebAuthFlow(
        {
          url: backendLoginUrl.toString(),
          interactive: true,
        },
        (callbackUrl) => {
          if (chrome.runtime.lastError || !callbackUrl) {
            return reject(
              new Error(
                `launchWebAuthFlow error: ${
                  chrome.runtime.lastError?.message || "No callback URL received from backend redirect"
                }`
              )
            )
          }
          
          // console.log(`[OAuth] Received callback URL: ${callbackUrl}`);

          // Parse the parameters from the final redirect URL (sent by your backend /auth/callback)
          const urlParams = new URLSearchParams(callbackUrl.split('?')[1] || "");
          const id_token = urlParams.get("id_token");
          const error = urlParams.get("error"); // Check if backend indicated an error

          if (error) {
            return reject(new Error(`OAuth callback error from backend: ${error}`))
          }

          if (!id_token) {
            // console.error("[OAuth] No id_token found in callback URL:", callbackUrl);
            return reject(
              new Error('No id_token parameter returned in callback URL from backend.')
            )
          }
          
          // console.log("[OAuth] Extracted id_token successfully.");
          resolve({ id_token }); // Resolve with the id_token
        }
      )
    })
  }

  /**
   * Initiates the OAuth flow, obtains an authorization code, exchanges for tokens, stores them.
   */
  public async login(): Promise<TokenResponse> { // Keep TokenResponse for structure, but focus on id_token
    try {
      // console.log("Starting login flow...");
      const authResult = await this.launchWebAuthFlow(); // Gets { id_token }
      const id_token = authResult.id_token;
      // console.log("ID Token obtained from auth flow.");

      // Backend now handles token storage via /auth/callback.
      // We just need to store the relevant parts locally if needed.
      // For WebSocket connection, we primarily need the id_token.
      // The structure of TokenResponse might need adjustment if refresh/access tokens aren't sent back.
      
      // Construct a minimal TokenResponse for local storage/use
      // We don't get access/refresh tokens directly back here anymore.
      // We rely on the id_token to get the wsToken later.
      const minimalTokenResponse: Partial<TokenResponse> = { 
          id_token: id_token,
          // access_token: ??? // Not available directly from this flow
          // refresh_token: ??? // Stays on backend
          // expires_in: ??? 
          // expiryTimestamp: ??? // Need to decode id_token to get expiry
          // email: ??? // Need to decode id_token
      };

      // Decode id_token to get expiry and email for local storage/use
      try {
          const payload = id_token.split(".")[1];
          const decoded = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
          minimalTokenResponse.expiryTimestamp = decoded.exp * 1000; // exp is in seconds
          minimalTokenResponse.email = decoded.email;
          // We can make up a placeholder expires_in based on expiryTimestamp
          minimalTokenResponse.expires_in = Math.max(0, Math.floor((minimalTokenResponse.expiryTimestamp - Date.now()) / 1000));
          // Add dummy values for other fields if needed by downstream code expecting TokenResponse structure
          minimalTokenResponse.access_token = "managed_by_backend"; 
          minimalTokenResponse.token_type = "Bearer";
          minimalTokenResponse.scope = decoded.scope || "openid email profile https://mail.google.com/"; // Get scope if present

      } catch(e) {
          console.error("Failed to decode id_token received from callback", e);
          throw new Error("Received invalid id_token from backend.");
      }

      // console.log("Storing minimal token response locally...");
      await this.storage.set("tokenResponse", minimalTokenResponse as TokenResponse); // Store the processed data

      // The `connectWebSocket` function will now use this stored id_token.
      // No need to call backend registration here, it happened in /auth/callback.

      return minimalTokenResponse as TokenResponse;

    } catch (error) {
      console.error("Error in login flow:", error);
      // Ensure storage is cleared on error
      await this.storage.remove("tokenResponse");
      throw error;
    }
  }

  /**
   * Returns the current TokenResponse from storage (or null if none).
   */
  public async getTokenResponse(): Promise<TokenResponse | null> {
    const tokenResponse = await this.storage.get<any>("tokenResponse");
    
    if (!tokenResponse) return null;
    
    // Handle migration from old format (expiryDate) to new format (expiryTimestamp)
    if (tokenResponse.expiryDate && !tokenResponse.expiryTimestamp) {
      // console.log("Migrating token format from expiryDate to expiryTimestamp");
      
      // Convert the old stored tokenResponse to the new format
      const migratedTokenResponse: TokenResponse = {
        access_token: tokenResponse.access_token,
        refresh_token: tokenResponse.refresh_token,
        expires_in: tokenResponse.expires_in,
        token_type: tokenResponse.token_type,
        scope: tokenResponse.scope,
        id_token: tokenResponse.id_token,
        expiryTimestamp: Date.now() + 300000 // Add 5 minutes to current time to allow for refresh
      };
      
      // Store the migrated token
      await this.storage.set("tokenResponse", migratedTokenResponse);
      return migratedTokenResponse;
    }
    
    return tokenResponse;
  }

  /**
   * Clears local token data, calls backend logout, and attempts to revoke the token if applicable.
   */
  public async logout(): Promise<void> {
    try {
      const tokenResponse = await this.getTokenResponse();

      if (tokenResponse && tokenResponse.id_token) {
        if (config.BACKEND_URL) {
          try {
            // console.log("[OAuthManager] Calling backend /auth/logout");
            const response = await fetch(`${config.BACKEND_URL}/auth/logout`, {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${tokenResponse.id_token}`,
                'Content-Type': 'application/json',
              },
            });
            if (!response.ok) {
              const errorData = await response.json().catch(() => ({ message: 'Failed to logout from backend, unknown error' }));
              // console.error('Backend logout failed:', response.status, errorData);
            } else {
              // console.log('[OAuthManager] Successfully logged out from backend.');
            }
          } catch (fetchError) {
            console.error('[OAuthManager] Error calling backend logout endpoint:', fetchError);
          }
        } else {
          // console.error("Backend URL is not configured. Skipping backend logout.");
        }
      } else {
        // console.warn('[OAuthManager] No ID token found locally. Skipping backend logout call.');
      }

      // Attempt to revoke Google token (mostly symbolic as client doesn't hold real access token)
      await this.revokeGoogleAccessTokenInternally(tokenResponse); 

      // Explicitly tell background to close WebSocket
      try {
        // console.log("[OAuthManager] Requesting background script to close WebSocket.");
        await chrome.runtime.sendMessage({ action: "explicitWsClose" });
        // console.log("[OAuthManager] Sent explicitWsClose message to background.");
      } catch (e: any) {
        // Error sending message is fine if background isn't active or listening (e.g. during uninstall)
        // console.warn("[OAuthManager] Could not send explicitWsClose to background (it might be inactive):", e.message);
      }

    } catch (error) {
      console.error("Error during logout process:", error)
    } finally {
      // Always clear local storage as the primary client-side logout action
      await this.storage.remove("tokenResponse")
      // console.log("[OAuthManager] Local tokenResponse cleared.");
    }
  }

  /**
   * Internal helper to attempt revoking Google's access token.
   * Note: With the current flow, the client might only have a placeholder access_token.
   */
  private async revokeGoogleAccessTokenInternally(tokenResponse: TokenResponse | null): Promise<void> {
    // The access_token stored by this oauthManager is often a placeholder like "managed_by_backend".
    // Revoking it with Google won't achieve much. True revocation should happen on the backend.
    // However, if a real access_token somehow was stored, this would attempt to revoke it.
    if (tokenResponse?.access_token && tokenResponse.access_token !== "managed_by_backend") {
      try {
        // console.log(`[OAuthManager] Attempting to revoke Google access token: ${tokenResponse.access_token.substring(0,10)}...`);
        const response = await fetch("https://oauth2.googleapis.com/revoke", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: `token=${encodeURIComponent(tokenResponse.access_token)}`,
        })

        if (!response.ok) {
          const errorText = await response.text();
          // console.warn(`[OAuthManager] Google token revocation request failed: ${response.status} ${errorText}`);
          // Not throwing an error here as backend logout is more critical and local storage clear will happen.
        } else {
          // console.log("[OAuthManager] Google access token revocation request successful (if token was valid).");
        }
      } catch (error) {
        // console.warn("[OAuthManager] Error sending Google token revocation request:", error)
      }
    } else {
      // console.log("[OAuthManager] Skipping Google access token revocation on client-side (no real access token or placeholder found).");
    }
  }

  /**
   * DEPRECATED or for specific use cases: Revokes the current stored access token via Google's revoke endpoint.
   * Prefer backend-initiated revocation for tokens stored on the backend.
   */
  public async revokeAccessToken(): Promise<void> {
    // console.warn("[OAuthManager] revokeAccessToken() called. Note: client-side revocation is limited if real tokens are backend-managed.");
    const tokenResponse = await this.getTokenResponse();
    await this.revokeGoogleAccessTokenInternally(tokenResponse);
    // This method might be called directly by UI, so ensure local tokens are also cleared if intent is full logout.
    // However, the main `logout` method is now more comprehensive.
  }

  /**
   * Check if the token is expired based on `expiryTimestamp`.
   */
  private isTokenExpired(tokenResponse: TokenResponse): boolean {
    if (!tokenResponse || typeof tokenResponse.expiryTimestamp !== 'number') {
      return true; // Invalid or missing timestamp
    }
    // Check expiryTimestamp (obtained from decoding id_token)
    const expirationBuffer = 5 * 60 * 1000 // 5 minutes
    return tokenResponse.expiryTimestamp <= Date.now() + expirationBuffer
  }

  /**
   * Check if a user is currently authenticated with a valid token
   */
  public async isAuthenticated(): Promise<boolean> {
    const tokenResponse = await this.getTokenResponse();
    return tokenResponse !== null && !this.isTokenExpired(tokenResponse);
  }
}

export const oauthManager = new OAuthManager()

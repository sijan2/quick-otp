import { DurableObject } from "cloudflare:workers";
import { encryptToken, decryptToken, refreshAccessToken } from '../services/authService';

export interface TokenData {
  encryptedRefreshToken: string;
  encryptedAccessToken: string;
  expiry: number;
  googleUserId: string;
  email: string;
  historyId: string | null;
  watchedLabelIds?: string[];
  otpLabelId: string | null;
  otpFilterId: string | null;
  isGmailAutomationSetup: boolean;
  encryptedIdToken?: string | null;
  moveToTrash?: boolean;
}

export class TokenStoreDO extends DurableObject<Env> {
  protected env: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.env = env;
    // Keep constructor lightweight
  }

  /* Hiding this fetch method as it appears unused by index.ts,
  // which interacts with TokenStoreDO via direct method calls.
  // This reduces attack surface. Test thoroughly before final removal.
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === "POST") {
        // Handle token storage
        if (path === "/store-tokens") {
          const data = await request.json<{ userId: string; email: string; accessToken: string; refreshToken: string; expiryTimeSeconds: number; }>();
          await this.storeTokens(data.userId, data.email, data.accessToken, data.refreshToken, data.expiryTimeSeconds);
          return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" }});
        }

        // Handle historyId update
        if (path === "/update-history-id") {
          const data = await request.json<{ userId: string; historyId: string }>();
          await this.updateHistoryId(data.userId, data.historyId);
          return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" }});
        }
      }

      if (request.method === "GET") {
        // Get token by userId
        if (path === "/get-token-by-user-id") {
          const userId = url.searchParams.get("userId");
          if (!userId) {
            return new Response(JSON.stringify({ error: "Missing userId parameter" }), { status: 400, headers: { "Content-Type": "application/json" }});
          }
          const tokenData = await this.getTokenByUserId(userId);
          return new Response(JSON.stringify(tokenData), { headers: { "Content-Type": "application/json" }});
        }

        // Get userId by email
        if (path === "/get-user-id-by-email") {
          const email = url.searchParams.get("email");
          if (!email) {
            return new Response(JSON.stringify({ error: "Missing email parameter" }), { status: 400, headers: { "Content-Type": "application/json" }});
          }
          const userId = await this.getUserIdByEmail(email);
          return new Response(JSON.stringify({ userId }), { headers: { "Content-Type": "application/json" }});
        }

        // Get valid access token
        if (path === "/get-valid-access-token") {
          const userId = url.searchParams.get("userId");
          if (!userId) {
            return new Response(JSON.stringify({ error: "Missing userId parameter" }), { status: 400, headers: { "Content-Type": "application/json" }});
          }
          try {
            const accessToken = await this.getValidAccessToken(userId);
            return new Response(JSON.stringify({ accessToken }), { headers: { "Content-Type": "application/json" }});
          } catch (error: any) {
            return new Response(JSON.stringify({ error: error.message }), { status: 404, headers: { "Content-Type": "application/json" }});
          }
        }
      }

      return new Response("Not found", { status: 404 });
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error in fetch handler: ${error.message}`);
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { "Content-Type": "application/json" }});
    }
  }
  */

  // Store token data in DO state
  async storeTokens(
    userId: string,
    email: string,
    accessToken: string,
    refreshToken: string,
    expiryTimeSeconds: number,
    initialWatchedLabelIds: string[] = [],
    idToken?: string | null // Added optional idToken for initial storage
  ): Promise<void> {
    try {
      const encryptPromises = [
        encryptToken(refreshToken, this.env.TOKEN_ENCRYPTION_KEY),
        encryptToken(accessToken, this.env.TOKEN_ENCRYPTION_KEY),
      ];
      if (idToken) {
        encryptPromises.push(encryptToken(idToken, this.env.TOKEN_ENCRYPTION_KEY));
      }

      const [encryptedRefreshToken, encryptedAccessToken, idTokenEncryptedResult] = await Promise.all(encryptPromises);
      const encryptedIdToken = idToken ? idTokenEncryptedResult : null;

      const existingTokenData = await this.ctx.storage.get<TokenData>(`user:${userId}`);

      // Explicitly handle potential undefined from older stored objects
      const ehistoryId = existingTokenData?.historyId;
      const ewatchedLabelIds = existingTokenData?.watchedLabelIds;
      const eotpLabelId = existingTokenData?.otpLabelId;
      const eotpFilterId = existingTokenData?.otpFilterId;
      const eisGmailAutomationSetup = existingTokenData?.isGmailAutomationSetup;
      const emoveToTrash = existingTokenData?.moveToTrash;

      const tokenData: TokenData = {
        encryptedRefreshToken,
        encryptedAccessToken,
        expiry: expiryTimeSeconds,
        googleUserId: userId,
        email,
        historyId: ehistoryId === undefined ? null : ehistoryId,
        watchedLabelIds: ewatchedLabelIds === undefined ? initialWatchedLabelIds : ewatchedLabelIds,
        otpLabelId: eotpLabelId === undefined ? null : eotpLabelId,
        otpFilterId: eotpFilterId === undefined ? null : eotpFilterId,
        isGmailAutomationSetup: eisGmailAutomationSetup === undefined ? false : eisGmailAutomationSetup,
        encryptedIdToken: existingTokenData?.encryptedIdToken === undefined ? encryptedIdToken : (encryptedIdToken ?? existingTokenData.encryptedIdToken), // Preserve if not newly provided, else use new one
        moveToTrash: emoveToTrash === undefined ? false : emoveToTrash
      };

      await this.ctx.storage.put(`user:${userId}`, tokenData);
      await this.ctx.storage.put(`email:${email}`, userId);
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error storing tokens for ${userId}: ${error.message}`);
      throw error;
    }
  }

  // Get token by userId
  async getTokenByUserId(userId: string): Promise<TokenData | null> {
    try {
      const tokenData = await this.ctx.storage.get<TokenData>(`user:${userId}`);
      return tokenData || null;
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error getting token for ${userId}: ${error.message}`);
      return null;
    }
  }

  // Get userId by email
  async getUserIdByEmail(email: string): Promise<string | null> {
    try {
      const userId = await this.ctx.storage.get<string>(`email:${email}`);

      if (!userId) {
        console.log(`[TokenStoreDO] No user found for email: ${email}`);
        return null;
      }

      console.log(`[TokenStoreDO] Found user ID: ${userId} for email: ${email}`);
      return userId;
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error getting userId for ${email}: ${error.message}`);
      return null;
    }
  }

  // Update historyId in token data
  async updateHistoryId(userId: string, historyId: string | null): Promise<void> {
    try {
      const tokenData = await this.getTokenByUserId(userId);
      if (!tokenData) {
        console.warn(`[TokenStoreDO] No token data for user ${userId} to update historyId.`);
        return;
      }
      if (tokenData.historyId === historyId) {
        console.log(`[TokenStoreDO] HistoryId ${historyId} same as current for user ${userId}, skipping update`);
        return;
      }
      tokenData.historyId = historyId;
      await this.ctx.storage.put(`user:${userId}`, tokenData);
      console.log(`[TokenStoreDO] Updated historyId to ${historyId || 'null'} for user ${userId}`);
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error in updateHistoryId for ${userId}: ${error.message}`);
    }
  }

  // Get a valid access token, refreshing if necessary
  async getValidAccessToken(userId: string): Promise<string> {
    const tokenData = await this.getTokenByUserId(userId);

    if (!tokenData) {
      throw new Error(`No token data found for user ${userId}`);
    }

    // Check if token is expired (with a 5-minute buffer)
    const now = Math.floor(Date.now() / 1000);
    if (tokenData.expiry > now + 300) {
      return await decryptToken(tokenData.encryptedAccessToken, this.env.TOKEN_ENCRYPTION_KEY);
    }

    console.log(`[TokenStoreDO: ${userId}] Access token expired or nearing expiry. Attempting refresh.`);
    try {
      // Token is expired, refresh it
      const rawRefreshToken = await decryptToken(tokenData.encryptedRefreshToken, this.env.TOKEN_ENCRYPTION_KEY);

      // Call the authService's refreshAccessToken which now returns more data
      const refreshedGoogleData = await refreshAccessToken(rawRefreshToken, this.env.GOOGLE_CLIENT_ID, this.env.GOOGLE_CLIENT_SECRET);

      const newRawAccessToken = refreshedGoogleData.access_token;
      const expiresIn = refreshedGoogleData.expires_in;
      const newRawIdToken = refreshedGoogleData.id_token; // This might be undefined
      const newExpiryTimestamp = Math.floor(Date.now() / 1000) + expiresIn;

      // Use the new method to update all tokens
      await this.updateTokensAfterRefresh(
        userId,
        newRawAccessToken,
        newExpiryTimestamp,
        newRawIdToken // Pass it through
      );

      console.log(`[TokenStoreDO] Refreshed tokens for user ${userId} via getValidAccessToken flow.`);

      return newRawAccessToken; // Return the new access token
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error refreshing token for ${userId} within getValidAccessToken: ${error.message}`);
      // If refresh fails (e.g. invalid_grant), we might want to delete the user's tokens
      if (error.message && (error.message.includes('invalid_grant') || error.message.includes('Token has been expired or revoked'))) {
        console.warn(`[TokenStoreDO: ${userId}] Refresh token is invalid during getValidAccessToken. Deleting user tokens.`);
        try {
          await this.deleteUser(userId); // Clear out stale data
        } catch (deleteError: any) {
          console.error(`[TokenStoreDO: ${userId}] Failed to delete user tokens after invalid_grant in getValidAccessToken: ${deleteError.message}`);
        }
      }
      throw new Error(`Failed to refresh token: ${error.message}`);
    }
  }

  // Update watchedLabelIds in token data
  async updateWatchedLabelIds(userId: string, labelIds: string[]): Promise<void> {
    try {
      const tokenData = await this.getTokenByUserId(userId);
      if (!tokenData) {
        throw new Error(`No token data found for user ${userId} when updating watched labels.`);
      }

      tokenData.watchedLabelIds = labelIds;
      await this.ctx.storage.put(`user:${userId}`, tokenData);
      console.log(`[TokenStoreDO] Updated watchedLabelIds to [${labelIds.join(', ')}] for user ${userId}`);
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error in updateWatchedLabelIds for user ${userId}: ${error.message}`);
      throw error;
    }
  }

  // Delete user data (tokens and email mapping)
  async deleteUser(userId: string): Promise<void> {
    try {
      console.log(`[TokenStoreDO] Attempting to delete data for user ${userId}`);
      // First, get the user data to find their email for the reverse lookup
      const tokenData = await this.ctx.storage.get<TokenData>(`user:${userId}`);

      // Delete the main user token data
      const deleteUserPromise = this.ctx.storage.delete(`user:${userId}`);
      let deleteEmailPromise = Promise.resolve(true); // Default to resolved promise

      if (tokenData && tokenData.email) {
        console.log(`[TokenStoreDO] User ${userId} has email ${tokenData.email}, deleting email mapping.`);
        deleteEmailPromise = this.ctx.storage.delete(`email:${tokenData.email}`);
      } else {
        console.warn(`[TokenStoreDO] No email found for user ${userId} when deleting, or tokenData was null. Skipping email mapping deletion.`);
      }

      await Promise.all([deleteUserPromise, deleteEmailPromise]);

      console.log(`[TokenStoreDO] Successfully deleted data for user ${userId}`);
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error deleting data for ${userId}: ${error.message}`);
      // Depending on policy, you might want to re-throw or handle differently
      throw error;
    }
  }

  async updateOtpLabelAndFilterIds(userId: string, otpLabelId: string | null, otpFilterId: string | null): Promise<void> {
    try {
      const tokenData = await this.getTokenByUserId(userId);
      if (!tokenData) {
        throw new Error(`No token data found for user ${userId} when updating OTP label/filter IDs.`);
      }
      tokenData.otpLabelId = otpLabelId;
      tokenData.otpFilterId = otpFilterId;
      await this.ctx.storage.put(`user:${userId}`, tokenData);
      console.log(`[TokenStoreDO] Updated OTP automation IDs for user ${userId}. LabelID: ${otpLabelId}, FilterID: ${otpFilterId}`);
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error updating OTP IDs for ${userId}: ${error.message}`);
      throw error;
    }
  }

  async markGmailAutomationSetupComplete(userId: string, setupState: boolean = true): Promise<void> {
    try {
      const tokenData = await this.getTokenByUserId(userId);
      if (!tokenData) {
        throw new Error(`No token data found for user ${userId} when marking Gmail automation setup.`);
      }
      tokenData.isGmailAutomationSetup = setupState;
      await this.ctx.storage.put(`user:${userId}`, tokenData);
      console.log(`[TokenStoreDO] Marked Gmail automation setup as ${setupState} for user ${userId}`);
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error marking Gmail setup for ${userId}: ${error.message}`);
      throw error;
    }
  }

  // Method to get only the decrypted refresh token
  async getRefreshToken(userId: string): Promise<string | null> {
    try {
      const tokenData = await this.getTokenByUserId(userId);
      if (tokenData && tokenData.encryptedRefreshToken) {
        return await decryptToken(tokenData.encryptedRefreshToken, this.env.TOKEN_ENCRYPTION_KEY);
      }
      return null;
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error getting refresh token for ${userId}: ${error.message}`);
      return null;
    }
  }

  // Update tokens after a successful refresh token grant from Google
  async updateTokensAfterRefresh(
    userId: string,
    newRawAccessToken: string,
    newExpiryTimestamp: number,
    newRawIdToken?: string | null // newRawIdToken can be string, null, or undefined
  ): Promise<void> {
    try {
      const tokenData = await this.getTokenByUserId(userId);
      if (!tokenData) {
        throw new Error(`No token data found for user ${userId} to update after refresh.`);
      }

      tokenData.encryptedAccessToken = await encryptToken(newRawAccessToken, this.env.TOKEN_ENCRYPTION_KEY);
      tokenData.expiry = newExpiryTimestamp;

      if (newRawIdToken) {
        tokenData.encryptedIdToken = await encryptToken(newRawIdToken, this.env.TOKEN_ENCRYPTION_KEY);
        console.log(`[TokenStoreDO: ${userId}] Updated with new encryptedIdToken.`);
      } else if (newRawIdToken === null) {
        // Explicitly clear if null is passed (Google didn't return one, or it should be cleared)
        tokenData.encryptedIdToken = null;
        console.log(`[TokenStoreDO: ${userId}] Cleared encryptedIdToken as new one was null.`);
      }
      // If newRawIdToken is undefined, we don't change the existing encryptedIdToken

      await this.ctx.storage.put(`user:${userId}`, tokenData);
      console.log(`[TokenStoreDO: ${userId}] Access token and expiry (and potentially ID token) updated after Google refresh grant.`);
    } catch (error: any) {
      console.error(`[TokenStoreDO: ${userId}] Error in updateTokensAfterRefresh: ${error.message}`);
      throw error;
    }
  }

  // Update moveToTrash preference
  async updateMoveToTrashPreference(userId: string, moveToTrash: boolean): Promise<void> {
    try {
      const tokenData = await this.getTokenByUserId(userId);
      if (!tokenData) {
        throw new Error(`No token data found for user ${userId} when updating move to trash preference.`);
      }
      if (tokenData.moveToTrash === moveToTrash) {
        console.log(`[TokenStoreDO] moveToTrash preference already set to ${moveToTrash} for user ${userId}. Skipping update.`);
        return;
      }
      tokenData.moveToTrash = moveToTrash;
      await this.ctx.storage.put(`user:${userId}`, tokenData);
      console.log(`[TokenStoreDO] Updated moveToTrash preference to ${moveToTrash} for user ${userId}`);
    } catch (error: any) {
      console.error(`[TokenStoreDO] Error in updateMoveToTrashPreference for user ${userId}: ${error.message}`);
      throw error;
    }
  }
}

import * as jose from 'jose';

// Consider moving these types to a shared types file (e.g., types/pubsub.ts or types.d.ts)
interface GmailNotification {
  emailAddress: string;
  historyId: string;
}

interface PubSubMessageData {
  data: string;
  messageId?: string;
  publishTime?: string;
  attributes?: Record<string, string>;
}

interface PubSubMessage {
  message?: PubSubMessageData;
  subscription?: string;
  // Add these properties for direct testing
  emailAddress?: string;
  historyId?: string;
  data?: string;
  // Allow other properties for flexible parsing
  [key: string]: any;
}

/**
 * Validate a JWT token from Google Cloud Pub/Sub
 *
 * @param token JWT token from the 'Authorization' header
 * @param audience Expected audience claim (your Worker URL)
 * @returns Whether the token is valid
 */
export async function validatePubSubJwt(token: string, audience: string): Promise<boolean> {
  try {
    const jwt = token.startsWith('Bearer ') ? token.substring(7) : token;
    const decodedToken = jose.decodeJwt(jwt);
    const now = Math.floor(Date.now() / 1000);

    if (decodedToken.exp && decodedToken.exp < now) {
      console.error('Token expired');
      return false;
    }
    if (decodedToken.nbf && decodedToken.nbf > now) {
      console.error('Token not yet valid');
      return false;
    }
    if (decodedToken.aud !== audience) {
      console.error(`Invalid audience: ${decodedToken.aud}, expected: ${audience}`);
      return false;
    }
    if (!decodedToken.iss || !decodedToken.iss.includes('google')) {
      console.error(`Invalid issuer: ${decodedToken.iss}`);
      return false;
    }
    // Note: Signature verification requires fetching Google's public keys.
    return true;
  } catch (error: any) {
    console.error('[PubSubService] Error validating Pub/Sub JWT:', error.message);
    return false;
  }
}

/**
 * Parse a Pub/Sub message body
 *
 * @param body The request body from Pub/Sub
 * @returns The parsed Gmail notification data
 */
export function parsePubSubMessage(body: PubSubMessage): GmailNotification {
  try {
    if (body.emailAddress && body.historyId) {
      return { emailAddress: body.emailAddress, historyId: body.historyId };
    }

    if (!body.message || !body.message.data) {
      console.warn('[PubSub Parser] Invalid PubSub format, attempting fallback.', body);
      const fallbackMessage = extractFallbackMessage(body);
      if (fallbackMessage) return fallbackMessage;
      throw new Error('Invalid PubSub: missing message.data and fallback failed');
    }

    const base64 = body.message.data.replace(/-/g, '+').replace(/_/g, '/');
    let decoded;
    try {
      decoded = atob(base64);
    } catch (error) {
      console.error('[PubSub Parser] Error decoding base64:', error);
      throw new Error(`Failed to decode base64 data: ${error instanceof Error ? error.message : String(error)}`);
    }

    try {
      const parsed = JSON.parse(decoded) as GmailNotification;
      if (!parsed.emailAddress || !parsed.historyId) {
        console.error('[PubSub Parser] Missing fields in decoded notification:', parsed);
        throw new Error('Missing fields in Gmail notification');
      }
      return parsed;
    } catch (error) {
      console.error('[PubSub Parser] Error parsing decoded JSON:', error);
      throw new Error(`Failed to parse JSON data: ${error instanceof Error ? error.message : String(error)}`);
    }
  } catch (error: any) {
    console.error('Error parsing Pub/Sub message overall:', error.message);
    throw new Error(`Failed to parse Pub/Sub message: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function extractFallbackMessage(body: any): GmailNotification | null {
  console.log('[PubSub Parser] Attempting fallback message extraction');
  try {
    if (body.data) {
      try {
        const decodedData = atob(body.data.replace(/-/g, '+').replace(/_/g, '/'));
        const parsedData = JSON.parse(decodedData);
        if (parsedData.emailAddress && parsedData.historyId) {
          console.log('[PubSub Parser] Fallback: Extracted message from body.data');
          return parsedData;
        }
      } catch (e) { /* Ignore and try next */ }
    }
    if (body.message && typeof body.message === 'object') {
      if (body.message.emailAddress && body.message.historyId) {
        console.log('[PubSub Parser] Fallback: Extracted message from body.message');
        return body.message;
      }
    }
    if (body.subscription) {
      const possiblePaths = [ body.subscription.message, body.subscription.data, body.subscription ];
      for (const path of possiblePaths) {
        if (path && path.emailAddress && path.historyId) {
          console.log('[PubSub Parser] Fallback: Extracted message from subscription data');
          return path;
        }
      }
    }
    // Removed development mock data
  } catch (e) {
    console.error('[PubSub Parser] Error in fallback message extraction:', e);
  }
  return null;
}

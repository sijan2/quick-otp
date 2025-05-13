import * as jose from 'jose';

// Assuming GoogleTokenResponse and GoogleIdTokenPayload types are available globally (e.g., from types.d.ts)

// Define a more specific type for Google's refresh token response
interface GoogleRefreshTokenResponse {
  access_token: string;
  expires_in: number; // Duration in seconds
  scope?: string;
  token_type?: string;
  id_token?: string; // id_token is often returned on refresh token grant
}

/**
 * Derives a 32-byte cryptographic key from a string using SHA-256.
 * This ensures the key material used for JWE is of the correct length for A256GCM.
 */
async function deriveKeyFromString(keyMaterial: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = encoder.encode(keyMaterial);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer); // SHA-256 output is 32 bytes
}

/**
 * Encrypt a token using JWE (dir, A256GCM) with a derived key.
 */
export async function encryptToken(token: string, encryptionKeyMaterial: string): Promise<string> {
  if (!token) {
    // Or handle as an error, depending on desired behavior for empty tokens
    console.warn("[AuthService-JWE] Attempted to encrypt an empty or null token.");
    return ''; // Return empty string or throw error
  }
  if (!encryptionKeyMaterial) {
    console.error("[AuthService-JWE] CRITICAL: Encryption key material is not provided for encryptToken.");
    throw new Error("Encryption key material is required.");
  }
  try {
    const key = await deriveKeyFromString(encryptionKeyMaterial);
    const jwe = await new jose.CompactEncrypt(
      new TextEncoder().encode(token)
    )
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(key);
    return jwe;
  } catch (error: any) {
    console.error(`[AuthService-JWE] Failed to encrypt token: ${error.message}`);
    throw new Error(`Token encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt a JWE token (dir, A256GCM) using a derived key.
 */
export async function decryptToken(encryptedToken: string, encryptionKeyMaterial: string): Promise<string> {
  if (!encryptedToken) {
    // Or handle as an error
    console.warn("[AuthService-JWE] Attempted to decrypt an empty or null token.");
    return '';
  }
  if (!encryptionKeyMaterial) {
    console.error("[AuthService-JWE] CRITICAL: Encryption key material is not provided for decryptToken.");
    throw new Error("Encryption key material is required.");
  }
  try {
    const key = await deriveKeyFromString(encryptionKeyMaterial);
    const { plaintext } = await jose.compactDecrypt(encryptedToken, key);
    return new TextDecoder().decode(plaintext);
  } catch (error: any) {
    // Log specific errors if JWE is malformed, key is wrong (decryption fails) etc.
    console.error(`[AuthService-JWE] Failed to decrypt token: ${error.message}. This could be due to a malformed token, incorrect key, or tampered data.`);
    // Depending on the error, 'error.code' might give more jose-specific details.
    // e.g., ERR_JWE_DECRYPTION_FAILED, ERR_JWE_INVALID
    throw new Error(`Token decryption failed: ${error.message}`);
  }
}

/**
 * Generate the Google OAuth authorization URL with PKCE
 */
export function generateAuthUrl(
  clientId: string,
  redirectUri: string,
  state: string,
  codeChallenge: string
): string {
  const scopes = [
    'openid',
    'email',
    'profile',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.labels',
    'https://www.googleapis.com/auth/gmail.settings.basic'
  ];

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: scopes.join(' '),
    access_type: 'offline',
    state: state,
    prompt: 'consent',
    code_challenge_method: 'S256',
    code_challenge: codeChallenge,
  });

  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

/**
 * Generate a code verifier and challenge for PKCE
 */
export async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
  // Generate a random code verifier
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const verifier = btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  // Generate the code challenge by hashing the verifier
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);

  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return { verifier, challenge };
}

/**
 * Exchange an authorization code for access and refresh tokens
 */
export async function exchangeCodeForTokens(
  code: string,
  codeVerifier: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string
): Promise<GoogleTokenResponse> {
  const params = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,
  });

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const error = await response.text();
    console.error(`[AuthService] Failed to exchange code for tokens: ${response.status} ${error}`);
    throw new Error(`Failed to exchange code for tokens: ${error}`);
  }

  return await response.json();
}

/**
 * Refresh an expired access token using a refresh token
 */
export async function refreshAccessToken(
  refreshToken: string,
  clientId: string,
  clientSecret: string
): Promise<GoogleRefreshTokenResponse> {
  const params = new URLSearchParams({
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'refresh_token',
  });

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const error = await response.text();
    console.error(`[AuthService] Failed to refresh access token: ${response.status} ${error}`);
    throw new Error(`Failed to refresh access token: ${error}`);
  }

  return await response.json();
}

// Google's public keys endpoint (JWKS URI)
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
// Expected Google issuer(s)
const GOOGLE_ISSUER = 'https://accounts.google.com'; // Or potentially ['accounts.google.com', 'https://accounts.google.com']

// Create a Remote JWK Set instance.
// This efficiently fetches and caches Google's public keys.
const JWKS = jose.createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));

// Assuming GoogleIdTokenPayload is defined globally or in types.d.ts
// interface GoogleIdTokenPayload extends jose.JWTPayload {
//   email?: string;
//   email_verified?: boolean;
//   name?: string;
//   picture?: string;
//   given_name?: string;
//   family_name?: string;
//   locale?: string;
//   hd?: string; // Hosted domain for GSuite users
// }

export async function verifyAndDecodeIdToken(
  idToken: string,
  expectedAudience: string,
  ignoreExpiry: boolean = false
): Promise<jose.JWTPayload & GoogleIdTokenPayload> {
  if (!idToken) {
    throw new Error('ID token is required.');
  }
  if (!expectedAudience) {
    console.error("[AuthService] CRITICAL: verifyAndDecodeIdToken called without expectedAudience (Client ID).");
    throw new Error('Configuration error: Missing expected audience for ID token verification.');
  }

  try {
    // First, attempt verification *with* expiry check by default.
    // We don't use maxTokenAge here as it relates to iat, not directly ignoring exp.
    const { payload } = await jose.jwtVerify(idToken, JWKS, {
      issuer: GOOGLE_ISSUER,
      audience: expectedAudience,
      algorithms: ['RS256'],
      // clockTolerance can be added if minor clock skews are an issue, e.g., '5 minutes'
    });
    // If successful, token is fully valid, including not being expired.
    return payload as jose.JWTPayload & GoogleIdTokenPayload;

  } catch (error: any) {
    const userIdForLog = (() => { try { return jose.decodeJwt(idToken).sub; } catch { return 'unknown'; } })();

    // If the error is specifically ERR_JWT_EXPIRED AND we are told to ignore expiry
    if (ignoreExpiry && error.code === 'ERR_JWT_EXPIRED') {
      console.warn(`[AuthService] ID token for user ${userIdForLog} (aud: ${expectedAudience}) is expired, but expiry is being IGNORED for this flow (e.g., refresh token lookup). Proceeding to decode claims without full re-validation of other aspects beyond initial attempt.`);
      // WARNING: At this point, we trust that if it failed *only* due to ERR_JWT_EXPIRED,
      // the other checks (signature, audience, issuer) in the initial jwtVerify attempt would have passed
      // or thrown different errors. This is a specific concession for the refresh token user lookup.
      try {
        const decodedPayload = jose.decodeJwt(idToken);
        // Perform manual aud and iss checks again on the decoded payload as a safeguard,
        // because we bypassed the full jwtVerify success path.
        if (decodedPayload.aud !== expectedAudience) {
            console.error(`[AuthService] Audience mismatch on decoded expired token for user ${userIdForLog}. Expected '${expectedAudience}', got '${decodedPayload.aud}'.`);
            throw new Error('Audience mismatch on (ignored-expiry) decoded token.');
        }
        // Allow both forms of issuer string for Google if necessary
        const  googleIssuers = [GOOGLE_ISSUER, 'accounts.google.com'];
        if (!decodedPayload.iss || !googleIssuers.includes(decodedPayload.iss)) {
            console.error(`[AuthService] Issuer mismatch on decoded expired token for user ${userIdForLog}. Expected one of '${googleIssuers.join(', ')}' or '', got '${decodedPayload.iss}'.`);
            throw new Error('Issuer mismatch on (ignored-expiry) decoded token.');
        }
        // We have the claims from an expired token, but signature/aud/iss were implicitly part of the initial try block's attempt.
        return decodedPayload as jose.JWTPayload & GoogleIdTokenPayload;
      } catch (decodeError: any) {
         console.error(`[AuthService] Failed to decode an expired token for user ${userIdForLog} even when ignoring expiry: ${decodeError.message}`);
         throw new Error(`Failed to extract claims from (ignored-expiry) token: ${decodeError.message}`);
      }
    }

    // Log the original error if it wasn't an ignored expiry case.
    console.error(`[AuthService] ID token verification failed for user ${userIdForLog} (aud: ${expectedAudience}): ${error.message} (Code: ${error.code})`);

    // Standard error mapping for other jose errors
    if (error.code === 'ERR_JWT_EXPIRED') { // This will now be hit if !ignoreExpiry
      throw new Error('Token expired');
    } else if (error.code === 'ERR_JWT_CLMS_INVLD') {
      throw new Error(`Token claims invalid (e.g., audience/issuer mismatch): ${error.message}`);
    } else if (error.code === 'ERR_JWKS_NO_MATCH' || error.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      throw new Error('Token signature validation failed.');
    }
    // Fallback for other errors from jose or unexpected issues
    throw new Error(`ID token validation failed: ${error.message}`);
  }
}

/**
 * Generates a signed JWT for WebSocket authentication.
 */
export async function generateWebSocketToken(
  userId: string,
  jwtSecret: string,
  expirationTimeSeconds: number = 3600 // Default to 1 hour
): Promise<string> {
  if (!jwtSecret) {
    throw new Error('WEBSOCKET_JWT_SECRET is not configured.');
  }
  const secretKey = new TextEncoder().encode(jwtSecret);
  const alg = 'HS256';

  const jwt = await new jose.SignJWT({ sub: userId })
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + expirationTimeSeconds)
    .sign(secretKey);

  return jwt;
}

/**
 * Verifies a signed JWT for WebSocket authentication.
 * Checks signature, expiration, and that the token's subject matches the expectedUserId.
 */
export async function verifyWebSocketToken(
  token: string,
  jwtSecret: string,
  expectedUserId: string
): Promise<jose.JWTPayload> {
  if (!jwtSecret) {
    throw new Error('WEBSOCKET_JWT_SECRET is not configured.');
  }
  const secretKey = new TextEncoder().encode(jwtSecret);
  const alg = 'HS256';

  try {
    const { payload } = await jose.jwtVerify(token, secretKey, {
      algorithms: [alg],
      // No need to specify audience or issuer here unless you set them during signing
    });

    if (!payload.sub || payload.sub !== expectedUserId) {
      throw new Error('Token subject (sub) does not match expected user ID.');
    }

    // jose.jwtVerify automatically checks 'exp' and 'iat' if present and valid.
    // It will throw if the token is expired.

    return payload;
  } catch (error: any) {
    // Log specific jose errors if needed, or rethrow a generic one
    console.error('[AuthService] WebSocket JWT verification failed:', error.message);
    throw new Error(`WebSocket token verification failed: ${error.message}`);
  }
}

/**
 * Revokes a Google OAuth token (access token or refresh token).
 */
export async function revokeGoogleToken(token: string): Promise<void> {
  if (!token) {
    console.warn("[AuthService] Attempted to revoke null/empty token.");
    return;
  }
  try {
    const response = await fetch('https://oauth2.googleapis.com/revoke', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ token: token }).toString(),
    });

    if (!response.ok) {
      // Google returns 200 OK on successful revocation, even if the token was already invalid or expired.
      // An error status here might indicate a problem with the request itself or Google's service.
      const errorText = await response.text();
      console.error(`[AuthService] Google token revocation failed: ${response.status} ${errorText}`);
      throw new Error(`Google token revocation failed with status ${response.status}: ${errorText}`);
    }
  } catch (error: any) {
    console.error(`[AuthService] Error during token revocation: ${error.message}`);
    throw error;
  }
}

// NEW FUNCTION to handle the refresh logic, interacting with TokenStoreDO
export async function processAndStoreRefreshedGoogleTokens(
  tokenStoreStub: any, // Using 'any' for now, replace with actual TokenStoreDO stub type if available
  userId: string,
  refreshTokenFromStore: string,
  clientId: string,
  clientSecret: string
): Promise<{ newIdToken?: string; newAccessToken: string; newExpiryTimestamp: number } | null> {
  try {
    console.log(`[AuthService: ${userId}] Attempting to refresh Google tokens using refresh_token.`);
    const refreshedTokenData = await refreshAccessToken(
      refreshTokenFromStore,
      clientId,
      clientSecret
    );

    const newAccessToken = refreshedTokenData.access_token;
    const expiresIn = refreshedTokenData.expires_in;
    const newIdToken = refreshedTokenData.id_token; // This might be undefined
    const newExpiryTimestamp = Math.floor(Date.now() / 1000) + expiresIn;

    console.log(`[AuthService: ${userId}] Google tokens refreshed. New access_token obtained. New id_token ${newIdToken ? 'obtained' : 'not obtained'}.`);

    // Update tokens in TokenStoreDO
    // The TokenStoreDO needs a method like 'updateRefreshedTokens'
    // For now, assuming it takes new access token, its expiry, and potentially new id_token
    await tokenStoreStub.updateTokensAfterRefresh(
      userId,
      newAccessToken,
      newExpiryTimestamp,
      newIdToken // Pass newIdToken if available, TokenStoreDO should handle it
    );
    console.log(`[AuthService: ${userId}] Successfully updated tokens in TokenStoreDO after refresh.`);

    return {
      newIdToken: newIdToken, // Will be undefined if not returned by Google
      newAccessToken: newAccessToken, // For backend use
      newExpiryTimestamp: newExpiryTimestamp // For backend use
    };

  } catch (error: any) {
    console.error(`[AuthService: ${userId}] Failed to process and store refreshed Google tokens: ${error.message}`);
    // Potentially handle specific errors, e.g., 'invalid_grant' for an expired/revoked refresh token
    if (error.message && (error.message.includes('invalid_grant') || error.message.includes('Token has been expired or revoked'))) {
      console.warn(`[AuthService: ${userId}] Refresh token is invalid. Full re-authentication required. Deleting user tokens.`);
      try {
        await tokenStoreStub.deleteUser(userId); // Clear out stale data
      } catch (deleteError: any) {
        console.error(`[AuthService: ${userId}] Failed to delete user tokens after invalid_grant: ${deleteError.message}`);
      }
    }
    // Do not re-throw here, allow the caller (route handler) to decide response
    return null;
  }
}

// Constants for Google Pub/Sub JWT Validation
// Google's public keys for validating JWTs from Pub/Sub push (often same as general Google certs)
const PUBSUB_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const PUBSUB_JWKS = jose.createRemoteJWKSet(new URL(PUBSUB_JWKS_URL));
// Expected issuer for Pub/Sub tokens (usually accounts.google.com, but confirm with your token)
const PUBSUB_ISSUER = 'https://accounts.google.com';

/**
 * Validates a JWT received from Google Cloud Pub/Sub push subscription.
 * @param token The JWT string from the Authorization header.
 * @param expectedAudience The audience expected in the JWT (usually your endpoint URL).
 * @param expectedServiceAccountEmail (Optional) The email of the service account expected to sign the token.
 * @returns The verified JWT payload.
 */
export async function validatePubSubJwt(
  token: string,
  expectedAudience: string,
  expectedServiceAccountEmail: string // Now required
): Promise<jose.JWTPayload> {
  if (!token) {
    throw new Error('Pub/Sub JWT is required.');
  }
  if (!expectedAudience) {
    console.error("[AuthService-PubSub] CRITICAL: validatePubSubJwt called without expectedAudience.");
    throw new Error('Configuration error: Missing expected audience for Pub/Sub JWT verification.');
  }
  if (!expectedServiceAccountEmail) { // Add check for required parameter
    console.error("[AuthService-PubSub] CRITICAL: validatePubSubJwt called without expectedServiceAccountEmail.");
    throw new Error('Configuration error: Missing expected service account email for Pub/Sub JWT verification.');
  }

  try {
    const { payload } = await jose.jwtVerify(token, PUBSUB_JWKS, {
      issuer: PUBSUB_ISSUER,
      audience: expectedAudience,
      algorithms: ['RS256'], // Google typically uses RS256 for these tokens
      // Default clock tolerance is used by jose.jwtVerify for 'exp' check
    });

    // Optional: Verify the service account email if provided
    if (payload.email !== expectedServiceAccountEmail) { // Now a mandatory check
      console.error(`[AuthService-PubSub] JWT email claim '${payload.email}' does not match expected service account '${expectedServiceAccountEmail}'. Validation failed.`);
      // Depending on strictness, you might throw an error here:
      throw new Error('JWT email claim does not match expected service account.');
    }
    if (!payload.email_verified) { // Consider making this check stricter too
        console.error(`[AuthService-PubSub] JWT for service account ${payload.email} has email_verified claim as false. Validation failed.`);
        // Depending on strictness:
        throw new Error('JWT email_verified claim is not true for service account.');
    }

    console.log(`[AuthService-PubSub] Pub/Sub JWT successfully validated for audience: ${expectedAudience}, issuer: ${payload.iss}, service_account_email: ${payload.email}`);
    return payload;
  } catch (error: any) {
    console.error(`[AuthService-PubSub] Pub/Sub JWT verification failed for audience ${expectedAudience}: ${error.message} (Code: ${error.code})`);
    if (error.code === 'ERR_JWT_EXPIRED') {
      throw new Error('Pub/Sub JWT expired');
    } else if (error.code === 'ERR_JWT_CLMS_INVLD') {
      throw new Error(`Pub/Sub JWT claims invalid (audience/issuer): ${error.message}`);
    } else if (error.code === 'ERR_JWKS_NO_MATCH' || error.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      throw new Error('Pub/Sub JWT signature validation failed.');
    }
    throw new Error(`Pub/Sub JWT validation failed: ${error.message}`);
  }
}

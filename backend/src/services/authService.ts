import * as CryptoJS from 'crypto-js';
import * as jose from 'jose';

// Assuming GoogleTokenResponse and GoogleIdTokenPayload types are available globally (e.g., from types.d.ts)

/**
 * Encrypt a token using AES encryption
 */
export function encryptToken(token: string, encryptionKey: string): string {
  return CryptoJS.AES.encrypt(token, encryptionKey).toString();
}

/**
 * Decrypt a token using AES decryption
 */
export function decryptToken(encryptedToken: string, encryptionKey: string): string {
  const bytes = CryptoJS.AES.decrypt(encryptedToken, encryptionKey);
  return bytes.toString(CryptoJS.enc.Utf8);
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
): Promise<{ access_token: string; expires_in: number }> {
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

/**
 * Decode and verify an ID token from Google
 */
export async function verifyAndDecodeIdToken(idToken: string, clientId: string): Promise<GoogleIdTokenPayload> {
  try {
    // For production, you should use a proper JWT verification library with all checks
    // This is a simplified version for demonstration
    const decodedToken = jose.decodeJwt(idToken);

    // Basic verification
    const now = Math.floor(Date.now() / 1000);

    if (decodedToken.exp && decodedToken.exp < now) {
      throw new Error('Token expired');
    }

    if (decodedToken.aud !== clientId) {
      throw new Error('Invalid audience');
    }

    if (decodedToken.iss !== 'https://accounts.google.com' &&
        decodedToken.iss !== 'accounts.google.com') {
      throw new Error('Invalid issuer');
    }

    return decodedToken as unknown as GoogleIdTokenPayload;
  } catch (error: any) {
    console.error('[AuthService] Error verifying ID token:', error.message);
    throw new Error(`Failed to verify ID token: ${error.message}`);
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

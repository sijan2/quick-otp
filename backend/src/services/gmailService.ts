import { TokenStoreDO, TokenData } from '../durable-objects/TokenStoreDO'; // Corrected path
import { WebSocketHub } from '../durable-objects/WebSocketHubDO'; // Import WebSocketHubDO
import { processEmailWithAI, AIProcessingConfig, AIProcessedEmail } from './aiService'; // Corrected path (already correct)
import { MASTER_TOKEN_STORE_ID } from '../constants'; // Import constant

/**
 * Set up Gmail API push notifications for a user
 */
export async function setupGmailWatch(
  accessToken: string,
  topicName: string,
  labelIds: string[] = ['INBOX']
): Promise<{ historyId: string }> {
  // ... implementation ...
  const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/watch', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      topicName,
      labelIds,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to set up Gmail watch: ${error}`);
  }

  return response.json();
}

/**
 * Stop Gmail API push notifications for a user
 */
export async function stopGmailWatch(accessToken: string): Promise<void> {
  // ... implementation ...
  const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/stop', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to stop Gmail watch: ${error}`);
  }
}

/**
 * Get Gmail history since a specific history ID
 */
export async function getGmailHistory(
  accessToken: string,
  startHistoryId: string,
  historyTypes: string[] = ['messageAdded', 'labelAdded']
): Promise<any> { // Consider defining a specific type for the history response
  // ... implementation ...
  const params = new URLSearchParams({
    startHistoryId,
  });

  // Correct: Append each historyType separately
  for (const type of historyTypes) {
    params.append('historyTypes', type);
  }

  const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/history?${params.toString()}`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to get Gmail history: ${error}`);
  }

  return response.json();
}

// Consider moving these Gmail-specific types to src/types/gmail.ts or keeping them in types.d.ts
interface GmailMessagePartBody {
  data?: string;
  size?: number;
}
interface GmailMessagePart {
  partId?: string;
  mimeType?: string;
  filename?: string;
  headers?: Array<{ name: string; value: string }>;
  body?: GmailMessagePartBody;
  parts?: GmailMessagePart[];
}
interface GmailMessage {
  id: string;
  threadId: string;
  labelIds?: string[];
  snippet?: string;
  historyId?: string;
  internalDate?: string;
  payload?: GmailMessagePart;
  sizeEstimate?: number;
  raw?: string;
}

/**
 * Fetches a full Gmail message object from the API.
 */
async function getGmailAPIMessage(accessToken: string, messageId: string): Promise<GmailMessage | null> {
  if (!messageId) {
    console.error("[GmailService] Invalid messageId provided to getGmailAPIMessage");
    return null;
  }
  try {
    const response = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`,
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[GmailService] Failed to fetch full email message ${messageId}: ${response.status} ${response.statusText}`, errorText);
      // throw new Error(`Failed to fetch email message ${messageId}: ${response.status} ${response.statusText}`);
      return null; // Return null on API error instead of throwing to allow processing other messages
    }
    return await response.json() as GmailMessage;
  } catch (error: any) {
    console.error(`[GmailService] Exception fetching full message ${messageId}: ${error.message}`);
    return null;
  }
}

/**
 * Parses the email body from a full GmailMessage object.
 */
function parseEmailBodyFromFullMessage(gmailMessage: GmailMessage | null): string {
  if (!gmailMessage || !gmailMessage.payload) return "";

  // Extracted getMessageBody logic
  const getMessageBodyRecursive = (payload: GmailMessagePart | undefined): string => {
    if (!payload) return "";
    let body = "";
    if (payload.body && payload.body.data) {
      try { body = atob(payload.body.data.replace(/-/g, "+").replace(/_/g, "/")); } catch (e) { console.error("Error decoding base64 body data:", e); return ""; }
    } else if (payload.parts && Array.isArray(payload.parts)) {
      for (const part of payload.parts) {
        if (part.mimeType === "text/plain") {
          if (part.body && part.body.data) { try { body = atob(part.body.data.replace(/-/g, "+").replace(/_/g, "/")); break; } catch (e) { console.error("Error decoding base64 part data (text/plain):", e); } }
        } else if (part.mimeType === "text/html") {
           if (part.body && part.body.data) { try { if (!body) { body = atob(part.body.data.replace(/-/g, "+").replace(/_/g, "/")); } } catch (e) { console.error("Error decoding base64 part data (text/html):", e); } }
        }
        if (part.parts && part.mimeType && part.mimeType.startsWith("multipart/")) {
          const nestedBody = getMessageBodyRecursive(part); // Recursive call
          if (nestedBody) { body = nestedBody; if (part.mimeType === "text/plain" || (part.mimeType === "text/html" && !body.includes("text/plain"))) { break; } }
        }
      }
    }
    return body;
  };
  return getMessageBodyRecursive(gmailMessage.payload);
}

/**
 * List Gmail labels for the user.
 */
export async function listGmailLabels(accessToken: string): Promise<Array<{ id: string; name: string; type: string }>> {
  try {
    const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/labels', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to list Gmail labels: ${error}`);
    }

    // Define expected structure of the API response
    interface LabelListResponse {
        labels?: Array<{ id: string; name: string; type: string; [key: string]: any }>; // Allow other potential fields
    }

    const data = await response.json() as LabelListResponse;
    // Ensure we return an array, filtering out any potentially null/undefined labels if necessary
    return (data.labels || []).filter((label: { id: string; name: string; type: string } | null | undefined) =>
        label && label.id && label.name && label.type
    ) as Array<{ id: string; name: string; type: string }>;
  } catch (error: any) {
    console.error(`[GmailService] Error listing labels: ${error.message}`);
    throw error;
  }
}

/**
 * Get a stub for the TokenStoreDO instance.
 */
function getTokenStoreDOStub(namespace: DurableObjectNamespace): TokenStoreDO {
  const objectId = namespace.idFromName(MASTER_TOKEN_STORE_ID); // Use locally defined constant
  return namespace.get(objectId) as unknown as TokenStoreDO;
}

/**
 * Get a stub for the WebSocketHubDO instance for a specific user.
 */
function getWebSocketHubDOStub(namespace: DurableObjectNamespace, userId: string): WebSocketHub {
    console.log(`[GmailHandler] Getting WebSocketHubDO stub for userId: ${userId}`);
    const id = namespace.idFromName(userId);
    return namespace.get(id) as unknown as WebSocketHub;
}

// Define types for parameters that would be passed from the worker environment
export interface GmailHandlerConfig {
  tokenStoreDONamespace: DurableObjectNamespace;
  webSocketHubDONamespace: DurableObjectNamespace;
  // AI Configuration
  provider: 'openai' | 'gemini';
  // OpenAI specific config
  openAIApiKey?: string;
  openAIModelName?: string;
  openAIEndpoint?: string;
  // Gemini specific config
  geminiApiKey?: string;
  geminiModelName?: string;
  geminiEndpoint?: string;
}

export interface GmailNotificationPayload { // Added export (might be needed by caller)
  emailAddress: string;
  historyId: string;
}

/**
 * Handles an incoming Gmail push notification.
 * Fetches new emails, extracts content, processes with AI, and notifies user via WebSocket.
 */
export async function handleGmailPushNotification(
  config: GmailHandlerConfig,
  notification: GmailNotificationPayload
): Promise<void> {
  console.log(`[GmailHandler: ${notification.emailAddress}] Received push notification, historyId: ${notification.historyId}`);

  const {
    tokenStoreDONamespace,
    webSocketHubDONamespace,
    provider,
    openAIApiKey,
    openAIModelName,
    openAIEndpoint,
    geminiApiKey,
    geminiModelName,
    geminiEndpoint
  } = config;
  const { emailAddress, historyId: newHistoryIdFromNotification } = notification;

  const tokenStoreStub = getTokenStoreDOStub(tokenStoreDONamespace);

  let userId: string | null = null;
  let accessToken: string | null = null;

  try {
    userId = await tokenStoreStub.getUserIdByEmail(emailAddress);
    if (!userId) {
      console.error(`[GmailHandler: ${emailAddress}] No user ID found. Skipping notification.`);
      return;
    }
    accessToken = await tokenStoreStub.getValidAccessToken(userId);
    console.log(`[GmailHandler: ${userId}] Obtained valid access token.`);

    // --- Check for active WebSocket connections ---
    try {
      const wsHubStub = getWebSocketHubDOStub(webSocketHubDONamespace, userId);
      // The base URL for DO-to-DO fetch can be arbitrary, e.g., http://do/ or even a relative path if interpreted correctly by the stub.
      // Using http://do/ for clarity as it signals an internal DO call.
      const connectionCountResponse = await wsHubStub.fetch(new Request('http://do/internal/get-connection-count', { method: 'GET' }));
      if (connectionCountResponse.ok) {
        const { activeConnections } = await connectionCountResponse.json() as { activeConnections: number };
        console.log(`[GmailHandler: ${userId}] Active WebSocket connections: ${activeConnections}`);
        if (activeConnections === 0) {
          console.log(`[GmailHandler: ${userId}] No active WebSocket connections. Skipping email processing for this notification.`);
          // Update historyId even if skipping, to acknowledge the notification and prevent re-processing if user connects later with this old historyId.
          const tokenDataForHistoryUpdate = await tokenStoreStub.getTokenByUserId(userId);
          const previousHistoryIdForSkip = tokenDataForHistoryUpdate?.historyId;
          if (newHistoryIdFromNotification && (!previousHistoryIdForSkip || newHistoryIdFromNotification !== previousHistoryIdForSkip)) {
            console.log(`[GmailHandler: ${userId}] Updating history ID to ${newHistoryIdFromNotification} after skipping due to no active connections.`);
            await tokenStoreStub.updateHistoryId(userId, newHistoryIdFromNotification);
          }
          return; // Skip further processing
        }
      } else {
        // Log error but continue processing if connection count check fails, not to block essential OTPs.
        console.warn(`[GmailHandler: ${userId}] Failed to get active WebSocket connection count. Status: ${connectionCountResponse.status}. Proceeding with email processing.`);
      }
    } catch (wsCheckError: any) {
      console.warn(`[GmailHandler: ${userId}] Error checking WebSocket connections: ${wsCheckError.message}. Proceeding with email processing.`);
    }
    // --- End WebSocket connection check ---

    const tokenData = await tokenStoreStub.getTokenByUserId(userId);
    if (!tokenData) {
        console.error(`[GmailHandler: ${userId}] Critical: No token data found. Skipping.`);
        return;
    }
    const watchedLabelIds = tokenData.watchedLabelIds || []; // Default to empty array
    const previousHistoryId = tokenData.historyId;

    // If no labels are being watched, do not proceed further.
    if (!watchedLabelIds || watchedLabelIds.length === 0) {
        console.log(`[GmailHandler: ${userId}] No labels are configured for watching. Skipping history processing.`);
        // Optionally, ensure watch is stopped if it somehow exists?
        // try { await stopGmailWatch(accessToken); } catch(e) { /* ignore */ }
        // It might also be good to update the history ID to the current one to prevent re-processing old notifications
        // if this state is reached, but that depends on desired behavior if user later adds labels.
        // For now, just skip processing.
        if (newHistoryIdFromNotification && (!previousHistoryId || newHistoryIdFromNotification !== previousHistoryId)) {
             console.log(`[GmailHandler: ${userId}] No watched labels, but new history ID detected. Updating history ID to ${newHistoryIdFromNotification} to acknowledge notification.`);
             await tokenStoreStub.updateHistoryId(userId, newHistoryIdFromNotification);
        }
        return;
    }

    console.log(`[GmailHandler: ${userId}] Watched Labels: [${watchedLabelIds.join(', ')}], Previous History ID: ${previousHistoryId || 'None'}.`);

    const startHistoryId = previousHistoryId || newHistoryIdFromNotification;
    if (!startHistoryId) {
        console.warn(`[GmailHandler: ${userId}] No valid startHistoryId. Using notification history ID: ${newHistoryIdFromNotification} to prevent loops.`);
        if (!newHistoryIdFromNotification) {
            console.error(`[GmailHandler: ${userId}] CRITICAL: Both previousHistoryId and newHistoryIdFromNotification are null. Cannot process history.`);
            return;
        }
    }

    console.log(`[GmailHandler: ${userId}] Fetching history since ${startHistoryId || newHistoryIdFromNotification}...`);
    const historyResponse = await getGmailHistory(accessToken, startHistoryId || newHistoryIdFromNotification);
    const currentHistoryId = historyResponse.historyId;
    console.log(`[GmailHandler: ${userId}] Fetched history. Current server history ID: ${currentHistoryId}`);

    const messagesToConsider = new Map<string, { id: string; threadId?: string; labelsToAdd?: string[]; labelsToRemove?: string[] }>();
    if (historyResponse.history && historyResponse.history.length > 0) {
      for (const historyItem of historyResponse.history) {
        if (historyItem.messagesAdded) {
          for (const ma of historyItem.messagesAdded) {
            if (ma.message && ma.message.id) {
              if (!messagesToConsider.has(ma.message.id)) {
                messagesToConsider.set(ma.message.id, { id: ma.message.id, threadId: ma.message.threadId });
              }
            }
          }
        }
        if (historyItem.labelsAddedOnMessages) {
          for (const la of historyItem.labelsAddedOnMessages) {
            if (la.message && la.message.id && la.labelIds && la.labelIds.some((labelId: string) => watchedLabelIds.includes(labelId))) {
              if (!messagesToConsider.has(la.message.id)) {
                messagesToConsider.set(la.message.id, { id: la.message.id, threadId: la.message.threadId });
              }
              const existing = messagesToConsider.get(la.message.id)!;
              existing.labelsToAdd = [...(existing.labelsToAdd || []), ...la.labelIds.filter((id: string) => watchedLabelIds.includes(id))];
            }
          }
        }
      }
    }

    const uniqueMessagesToProcess = Array.from(messagesToConsider.values());
    console.log(`[GmailHandler: ${userId}] Found ${uniqueMessagesToProcess.length} unique messages to potentially process.`);

    let notifiedCount = 0;
    for (const messageInfo of uniqueMessagesToProcess) {
      try {
        console.log(`[GmailHandler: ${userId}] Evaluating messageId: ${messageInfo.id}.`);

        const fullMessage = await getGmailAPIMessage(accessToken, messageInfo.id);
        if (!fullMessage || !fullMessage.labelIds) {
            console.warn(`[GmailHandler: ${userId}] Could not fetch full details or labels for messageId: ${messageInfo.id}. Skipping.`);
            continue;
        }

        const hasWatchedLabel = fullMessage.labelIds.some((labelId: string) => watchedLabelIds.includes(labelId));
        if (!hasWatchedLabel) {
            console.log(`[GmailHandler: ${userId}] MessageId: ${messageInfo.id} (labels: [${fullMessage.labelIds.join(', ')}]) does not have any of the watched labels [${watchedLabelIds.join(', ')}]. Skipping.`);
            continue;
        }
        console.log(`[GmailHandler: ${userId}] MessageId: ${messageInfo.id} has a watched label. Proceeding to get content.`);

        const emailContent = parseEmailBodyFromFullMessage(fullMessage);
        if (!emailContent) {
            console.warn(`[GmailHandler: ${userId}] No content extracted for messageId: ${messageInfo.id}. Skipping AI processing.`);
            continue;
        }

        const aiConfig: AIProcessingConfig = {
          provider,
          ...(provider === 'openai' && {
            openAIApiKey,
            ...(openAIModelName && { openAIModelName }),
            ...(openAIEndpoint && { openAIEndpoint }),
          }),
          ...(provider === 'gemini' && {
            geminiApiKey,
            ...(geminiModelName && { geminiModelName }),
            ...(geminiEndpoint && { geminiEndpoint }),
          }),
        };
        const processedData: AIProcessedEmail = await processEmailWithAI(emailContent, aiConfig);
        console.log(`[GmailHandler: ${userId}] AI processing complete for ${messageInfo.id}. OTP found: ${!!processedData.code}, URL found: ${!!processedData.url}.`);

        if (processedData.code || processedData.url) {
          let logMessage = `[GmailHandler: ${userId}] Sensitive data found by AI for messageId: ${messageInfo.id}.`;
          if (processedData.code) logMessage += ` Type: OTP (length: ${processedData.code.length}).`;
          if (processedData.url) logMessage += ` Type: URL (domain: ${safeGetDomain(processedData.url)}).`;
          console.log(logMessage);

          const wsHubStub = getWebSocketHubDOStub(webSocketHubDONamespace, userId);
          const wsMessage = {
            type: "OTP_RESULT",
            payload: {
              code: processedData.code || null,
              url: processedData.url || null,
              messageId: messageInfo.id,
              timestamp: Date.now()
            }
          };
          const notifyRequest = new Request('http://do/internal/notify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(wsMessage)
          });
          const notifyResponse = await wsHubStub.fetch(notifyRequest);
          if (!notifyResponse.ok) {
              console.error(`[GmailHandler: ${userId}] Failed to send notification via WebSocketHubDO. Status: ${notifyResponse.status}, Body: ${await notifyResponse.text().catch(()=>'N/A')}`);
          } else {
              notifiedCount++;
          }
        } else {
          console.log(`[GmailHandler: ${userId}] No OTP/URL found by AI for messageId: ${messageInfo.id}.`);
        }
      } catch (messageError: any) {
        console.error(`[GmailHandler: ${userId}] Error processing message ${messageInfo.id}: ${messageError.message ? messageError.message : messageError}`);
      }
    }
    console.log(`[GmailHandler: ${userId}] Finished processing messages. Notifications sent: ${notifiedCount}`);

    if (currentHistoryId) {
      if (previousHistoryId !== currentHistoryId) { // Check against previous, not startHistoryId, to ensure updates always happen if Google gives a new ID
           console.log(`[GmailHandler: ${userId}] Updating historyId from ${previousHistoryId || 'None'} to ${currentHistoryId}.`);
           await tokenStoreStub.updateHistoryId(userId, currentHistoryId);
      } else {
          console.log(`[GmailHandler: ${userId}] HistoryId ${currentHistoryId} same as previous. No update needed.`);
      }
    } else {
        console.warn(`[GmailHandler: ${userId}] No currentHistoryId returned. Cannot update historyId.`);
    }

  } catch (error: any) {
    const userIdForLog = userId || 'Unknown User';
    console.error(`[GmailHandler: ${userIdForLog}] Top-level error in handleGmailPushNotification for ${emailAddress}: ${error.message ? error.message : error}`);
  }
}

// Helper function to safely extract domain from URL for logging
function safeGetDomain(url: string | undefined): string {
  if (!url) return 'N/A';
  try {
    return new URL(url).hostname;
  } catch (e) {
    return 'Invalid URL';
  }
}

// --- Interfaces (Gmail specific, good to have defined) ---
interface GmailLabelAPI {
    id: string;
    name: string;
    type?: string;
    messageListVisibility?: string;
    labelListVisibility?: string;
}

interface ListLabelsResponse {
    labels?: GmailLabelAPI[];
}

interface GmailFilterAPI {
    id: string;
    criteria?: { query?: string; [key: string]: any };
    action?: { addLabelIds?: string[]; removeLabelIds?: string[]; [key: string]: any };
}

export interface SetupGmailAutomationResult {
    success: boolean;
    otpLabelId?: string | null;
    filterId?: string | null;
    message: string;
    labelEnsured: boolean;
    filterOperationAttempted: boolean;
}

// --- Helper Function to List All Gmail Filters ---
async function listGmailFilters(accessToken: string): Promise<GmailFilterAPI[]> {
  const listFiltersUrl = 'https://gmail.googleapis.com/gmail/v1/users/me/settings/filters';
  try {
    const response = await fetch(listFiltersUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      const errorText = await response.text(); // Read error text first
      console.error(`[GmailService] Failed to list Gmail filters: ${response.status} ${errorText}`);
      throw new Error(`Failed to list Gmail filters (Status: ${response.status}): ${errorText}`);
    }

    const responseBodyText = await response.text();
    if (!responseBodyText || responseBodyText.trim() === '') {
      console.log('[GmailService] List filters response empty (no filters exist).');
      return [];
    }

    // If body is not empty, then parse as JSON
    const data = JSON.parse(responseBodyText) as { filter?: GmailFilterAPI[] };
    return data.filter || []; // data.filter might still be undefined if JSON is {} but no 'filter' key
  } catch (error: any) {
    console.error(`[GmailService] Error in listGmailFilters: ${error.message}`);
    throw error;
  }
}

// --- Helper Function to Delete a Gmail Filter by ID ---
async function deleteGmailFilter(accessToken: string, filterId: string): Promise<boolean> {
  if (!filterId) {
    console.warn('[GmailService] Attempted to delete filter with no ID.');
    return false;
  }
  const deleteFilterUrl = `https://gmail.googleapis.com/gmail/v1/users/me/settings/filters/${filterId}`;
  console.log(`[GmailService] Deleting Gmail filter with ID: ${filterId}`);
  try {
    const response = await fetch(deleteFilterUrl, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      // It might return 404 if filter already deleted, which is acceptable.
      if (response.status === 404) {
        console.log(`[GmailService] Filter ${filterId} not found for deletion (already deleted or invalid ID).`);
        return true; // Consider it a success if it's already gone
      }
      const errorText = await response.text();
      console.error(`[GmailService] Failed to delete Gmail filter ${filterId}: ${response.status} ${errorText}`);
      throw new Error(`Failed to delete Gmail filter ${filterId}: ${response.statusText} - ${errorText}`);
    }
    console.log(`[GmailService] Successfully deleted Gmail filter ID: ${filterId}`);
    return true;
  } catch (error: any) {
    console.error(`[GmailService] Error in deleteGmailFilter for ID ${filterId}: ${error.message}`);
    throw error; // Re-throw
  }
}

// --- 1. Improved Filter Query Function (getOtpFilterQuery) ---
function getOtpFilterQuery(): string {
    const phrases = [
        "verification code", "otp", "one-time password", "confirm your email",
        "activation code", "confirmation link", "security code",
        "auth code", "authentication code", "your single-use code is",
        "follow this link to reset your mimo password",
        "sign in to your medium account",
        "you can confirm your account email through the link below",
        "you need to verify your email address", "complete your call of duty registration",
        "cheers to starting on the right foot. just wanted to make sure we have the right email.",
        "click on the button below to verify your email address",
        "click to confirm your new email address.", "enter the following password reset code",
        "please use this code to reset the password for the microsoft account",
        "we're happy you're here. let's get your email address verified",
        "enter this code to sign in", "please use the following code to confirm your identity",
        "your 6-digit code",
        "Secure link to log in to Claude.ai",
        "login code", "sign-in code", "Your login code", "is your login code",
        "Your verification code is", "is your verification code", "Your confirmation code is",
        "Your authentication code is", "Enter this code to log in", "Enter this code to verify",
        "Enter this code to confirm", "magic link", "log in with this link",
        "sign in with this link", "Verify your sign-in", "Confirm your login",
        "Validate your email address", "Use the following code", "Here is your code",
        "Your code is", "One-time code", "Your temporary code", "access code",
        "reset password",
        "password reset",
        "reset your password",
        "password reset link",
        "password reset instructions",
        "request to reset your password",
        "request to reset the password",
        "reset your account password",
        "password change request",
        "change your password",
        "link to reset your password",
        "recover your account",
        "recover your account password",
        "recover your account password link",
        "recover your account password instructions",
        "recover your account password request",
        "recover your account password request link",
        "recover your account password request instructions",
        "park your account",
        "park my account",
        "forgotten your password",
				"signed up for a new account or requested a password or email change",
				"You've requested to login with your email",
				"You've requested to change your email address",
    ];
    const uniquePhrases = [...new Set(phrases.map(p => p.toLowerCase().trim()))];
    return uniquePhrases.map(phrase => `"${phrase}"`).join(' OR ');
}

// --- 2. Ensure "otp" Label Exists (ensureOtpLabelWorker) ---
async function ensureOtpLabelWorker(accessToken: string, labelName: string = 'otp'): Promise<{ id: string | null, createdNow: boolean }> {
    const listLabelsUrl = 'https://gmail.googleapis.com/gmail/v1/users/me/labels';
    const createLabelUrl = 'https://gmail.googleapis.com/gmail/v1/users/me/labels';
    const targetLabelNameLower = labelName.toLowerCase();
    console.log(`[GmailService] Ensuring label "${labelName}" exists.`);
    try {
        const listResponse = await fetch(listLabelsUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` },
        });
        if (!listResponse.ok) {
            const errorText = await listResponse.text();
            console.error(`[GmailService] Failed to list Gmail labels: ${listResponse.status} ${errorText}`);
            throw new Error(`Failed to list Gmail labels: ${listResponse.statusText} - ${errorText}`);
        }
        const listData: ListLabelsResponse = await listResponse.json();
        const existingLabel = listData.labels?.find(label => label.name.toLowerCase() === targetLabelNameLower);
        if (existingLabel?.id) {
            console.log(`[GmailService] Label "${labelName}" already exists with ID: ${existingLabel.id}`);
            return { id: existingLabel.id, createdNow: false };
        }
        console.log(`[GmailService] Label "${labelName}" not found. Creating it...`);
        const createResponse = await fetch(createLabelUrl, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name: labelName,
                labelListVisibility: 'labelShow',
                messageListVisibility: 'show',
            }),
        });
        if (!createResponse.ok) {
            const errorText = await createResponse.text();
            console.error(`[GmailService] Failed to create label "${labelName}": ${createResponse.status} ${errorText}`);
            throw new Error(`Failed to create label "${labelName}": ${createResponse.statusText} - ${errorText}`);
        }
        const newLabel: GmailLabelAPI = await createResponse.json();
        if (newLabel.id) {
            console.log(`[GmailService] Label "${labelName}" created with ID: ${newLabel.id}`);
            return { id: newLabel.id, createdNow: true };
        } else {
            console.error(`[GmailService] Failed to create label "${labelName}", no ID in response.`);
            return { id: null, createdNow: false };
        }
    } catch (error: any) {
        console.error(`[GmailService] Error in ensureOtpLabelWorker for "${labelName}": ${error.message}`);
        throw error;
    }
}

// --- 3. Create (or Ensure) Filter Function (Modified Logic) ---
async function ensureOtpFilterWorker(
  accessToken: string,
  otpLabelId: string,
  expectedQuery: string,
  moveToTrash: boolean
): Promise<GmailFilterAPI | null> {
  console.log(`[ensureOtpFilterWorker V4] Ensuring single, up-to-date OTP filter for LabelID: ${otpLabelId}. MoveToTrash: ${moveToTrash}`);

  const existingFilters = await listGmailFilters(accessToken);
  let oldFilterDeleted = false;

  if (existingFilters && existingFilters.length > 0) {
    console.log(`[ensureOtpFilterWorker V4] Found ${existingFilters.length} existing filters. Checking for old OTP filters to remove...`);
    for (const filter of existingFilters) {
      if (filter.action?.addLabelIds?.includes(otpLabelId)) {
        // This filter applies our OTP label. We assume our app manages it.
        // Delete it to make way for the new/updated one.
        console.log(`[ensureOtpFilterWorker V4] Found filter (ID: ${filter.id}) that applies OTP label ${otpLabelId}. Deleting it.`);
        try {
          await deleteGmailFilter(accessToken, filter.id);
          oldFilterDeleted = true;
          console.log(`[ensureOtpFilterWorker V4] Successfully deleted old filter ID: ${filter.id}`);
        } catch (deleteError: any) {
          console.warn(`[ensureOtpFilterWorker V4] Failed to delete old filter ID: ${filter.id}. Error: ${deleteError.message}. Will proceed to create new filter anyway.`);
          // Continue, as the old filter might be orphaned or already gone.
        }
      }
    }
  } else {
    console.log("[ensureOtpFilterWorker V4] No existing filters found for the user.");
  }
  if (oldFilterDeleted) {
    console.log("[ensureOtpFilterWorker V4] Finished attempting to delete old OTP filters.");
  } else {
    console.log("[ensureOtpFilterWorker V4] No old OTP filters (that apply the specified label) found or deleted.");
  }

  // Always create a new filter with the latest query and actions.
  console.log(`[ensureOtpFilterWorker V4] Creating new OTP filter with query: ${expectedQuery.substring(0,100)}...`);
  const createFilterUrl = 'https://gmail.googleapis.com/gmail/v1/users/me/settings/filters';

  // Base action
  const action: { addLabelIds: string[]; removeLabelIds: string[] } = {
    addLabelIds: [otpLabelId],
    removeLabelIds: ['UNREAD'],
  };

  // Conditionally add TRASH label
  if (moveToTrash) {
    action.addLabelIds.push('TRASH');
    console.log(`[ensureOtpFilterWorker V4] Adding 'TRASH' label to filter action.`);
  }

  const filterPayload = {
      criteria: { query: expectedQuery },
      action: action, // Use the constructed action
  };
  // console.log(`[ensureOtpFilterWorker V3] New filter PAYLOAD: ${JSON.stringify(filterPayload)}`); // Keep for debugging if needed

  try {
      const response = await fetch(createFilterUrl, {
          method: 'POST',
          headers: {'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json'},
          body: JSON.stringify(filterPayload)
      });
      const responseStatus = response.status;
      const responseBodyText = await response.text();
      console.log(`[ensureOtpFilterWorker V4] Create Filter API STATUS: ${responseStatus}, BODY (first 500 chars): ${responseBodyText.substring(0, 500)}`);

      if (!response.ok) {
          console.error(`[ensureOtpFilterWorker V4] Create Filter API FAILED.`);
          return null;
      }
      const createdFilter: GmailFilterAPI = JSON.parse(responseBodyText);
      console.log(`[ensureOtpFilterWorker V4] Create Filter API SUCCESS. New Filter ID: ${createdFilter.id}`);
      return createdFilter;
  } catch (error: any) {
      console.error(`[ensureOtpFilterWorker V4] Create Filter API EXCEPTION: ${error.message}`);
      return null;
  }
}

export async function setupGmailOtpAutomation(
    accessToken: string,
    userId: string,
): Promise<SetupGmailAutomationResult> {
    console.log(`[GmailService: ${userId}] Initiating OTP automation setup.`);
    let labelResult: { id: string | null, createdNow: boolean } = { id: null, createdNow: false };
    let finalFilter: GmailFilterAPI | null = null;
    try {
        labelResult = await ensureOtpLabelWorker(accessToken, 'otp');
        if (!labelResult.id) {
            console.error(`[GmailService: ${userId}] OTP label setup step failed.`);
            return { success: false, message: 'Failed to ensure "otp" label.', otpLabelId: null, filterId: null, labelEnsured: false, filterOperationAttempted: false };
        }
        const expectedFilterQuery = getOtpFilterQuery();
        finalFilter = await ensureOtpFilterWorker(accessToken, labelResult.id, expectedFilterQuery, false);

        if (!finalFilter || !finalFilter.id) {
            console.error(`[GmailService: ${userId}] OTP filter setup step failed.`);
            return { success: false, message: 'Failed to ensure OTP filter.', otpLabelId: labelResult.id, filterId: null, labelEnsured: true, filterOperationAttempted: true };
        }
        const message = `User ${userId}: OTP automation setup complete. Label: ${labelResult.id}, Filter: ${finalFilter.id}.`;
        console.log(message);
        return {
            success: true, otpLabelId: labelResult.id, filterId: finalFilter.id,
            message: message, labelEnsured: true, filterOperationAttempted: true,
        };
    } catch (error: any) {
        console.error(`[GmailService: ${userId}] Overall EXCEPTION during OTP automation setup: ${error.message}`);
        return { success: false, message: error.message, otpLabelId: labelResult.id, filterId: finalFilter?.id || null, labelEnsured: !!labelResult.id, filterOperationAttempted: true };
    }
}

/**
 * Recreates the OTP filter based on the stored preference in TokenStoreDO.
 */
export async function recreateOtpFilter(
    accessToken: string,
    userId: string,
    tokenStoreStub: TokenStoreDO
): Promise<GmailFilterAPI | null> {
    console.log(`[GmailService: ${userId}] Recreating OTP filter based on stored preference.`);
    try {
        const tokenData = await tokenStoreStub.getTokenByUserId(userId);
        if (!tokenData) {
            throw new Error("No token data found for user.");
        }
        if (!tokenData.otpLabelId) {
            console.warn(`[GmailService: ${userId}] Cannot recreate filter: OTP Label ID is missing.`);
            return null;
        }

        const moveToTrash = tokenData.moveToTrash ?? false; // Default to false if undefined
        const expectedFilterQuery = getOtpFilterQuery();

        console.log(`[GmailService: ${userId}] Calling ensureOtpFilterWorker. LabelID: ${tokenData.otpLabelId}, MoveToTrash: ${moveToTrash}`);
        const updatedFilter = await ensureOtpFilterWorker(
            accessToken,
            tokenData.otpLabelId,
            expectedFilterQuery,
            moveToTrash
        );

        if (updatedFilter && updatedFilter.id && updatedFilter.id !== tokenData.otpFilterId) {
            console.log(`[GmailService: ${userId}] Filter recreated/updated. New Filter ID: ${updatedFilter.id}. Storing new ID.`);
            await tokenStoreStub.updateOtpLabelAndFilterIds(userId, tokenData.otpLabelId, updatedFilter.id);
        } else if (updatedFilter && updatedFilter.id) {
            console.log(`[GmailService: ${userId}] Filter recreated/verified. Filter ID remains: ${updatedFilter.id}.`);
        } else {
            console.error(`[GmailService: ${userId}] Failed to recreate OTP filter.`);
        }

        return updatedFilter;
    } catch (error: any) {
        console.error(`[GmailService: ${userId}] Error in recreateOtpFilter: ${error.message}`);
        throw error; // Re-throw to be handled by the caller (e.g., API endpoint)
    }
}

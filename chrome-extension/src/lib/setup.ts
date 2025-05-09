// ../lib/setup.ts

import { config } from './config';
import { oauthManager } from './oauth';

export interface GmailLabel {
  id: string;
  name: string;
  type: string; // 'system' or 'user'
}

// Fetch the list of all available Gmail labels
export async function listLabels(): Promise<GmailLabel[]> {
  const tokenResponse = await oauthManager.getTokenResponse(); 
  if (!tokenResponse?.id_token) {
    throw new Error('User not authenticated');
  }

  const response = await fetch(`${config.BACKEND_URL}/api/list-labels`, {
    headers: {
      'Authorization': `Bearer ${tokenResponse.id_token}`,
    },
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: 'Failed to list labels, unknown error' }));
    throw new Error(`Failed to list labels: ${errorData.message || response.statusText}`);
  }

  const data = await response.json();
  return (data.labels || []) as GmailLabel[];
}

// Fetch the list of currently watched label IDs
export async function getWatchedLabels(): Promise<string[]> {
  const tokenResponse = await oauthManager.getTokenResponse(); 
  if (!tokenResponse?.id_token) {
    throw new Error('User not authenticated');
  }

  const response = await fetch(`${config.BACKEND_URL}/api/get-watched-labels`, {
    headers: {
      'Authorization': `Bearer ${tokenResponse.id_token}`,
    },
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: 'Failed to get watched labels, unknown error' }));
    throw new Error(`Failed to get watched labels: ${errorData.message || response.statusText}`);
  }

  const data = await response.json();
  return (data.watchedLabelIds || []) as string[];
}

// Update the watched labels on the backend
export async function updateWatchedLabels(labelIds: string[]): Promise<void> {
  const tokenResponse = await oauthManager.getTokenResponse(); 
  if (!tokenResponse?.id_token) {
    throw new Error('User not authenticated');
  }

  const response = await fetch(`${config.BACKEND_URL}/api/update-watched-labels`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${tokenResponse.id_token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ labelIds }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: 'Failed to update watched labels, unknown error' }));
    throw new Error(`Failed to update watched labels: ${errorData.message || response.statusText}`);
  }
  // No specific data needed from response body on success usually
}

// Stop the current Gmail watch on the backend
export async function stopCurrentWatch(): Promise<void> {
  const tokenResponse = await oauthManager.getTokenResponse(); 
  if (!tokenResponse?.id_token) {
    throw new Error('User not authenticated');
  }

  const response = await fetch(`${config.BACKEND_URL}/api/stop-watch`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${tokenResponse.id_token}`,
      'Content-Type': 'application/json', // Content-Type needed even for no body sometimes
    },
    // No body needed for this request
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: 'Failed to stop watch, unknown error' }));
    throw new Error(`Failed to stop watch: ${errorData.message || response.statusText}`);
  }
  // No specific data needed from response body on success
}

import React, { useState, useEffect, useCallback } from "react"
import { oauthManager } from "../lib/oauth"
import { config } from "../lib/config"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Switch } from "@/components/ui/switch"
import { Label as UILabel } from "@/components/ui/label"

interface Label {
  id: string;
  name: string;
  type?: string;
}

interface OtpResult {
  code: string | null;
  url: string | null;
  messageId: string;
  timestamp: number;
}

interface TokenResponse {
  access_token: string
  refresh_token?: string
  expires_in: number
  token_type: string
  scope: string
  id_token?: string
  expiryTimestamp: number
  email?: string 
}

// --- Gmail label related helper functions (moved from setup.ts) ---
// These operate on the ID token that the Popup component already has, avoiding
// additional token refreshes performed inside lib/setup.ts.
async function listLabels(idToken?: string): Promise<Label[]> {
  if (!idToken) {
    throw new Error("User not authenticated")
  }
  const response = await fetch(`${config.BACKEND_URL}/api/list-labels`, {
    headers: {
      Authorization: `Bearer ${idToken}`,
    },
  })
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: "Failed to list labels" }))
    throw new Error(errorData.message || response.statusText)
  }
  const data = await response.json()
  return (data.labels || []) as Label[]
}

async function getWatchedLabels(idToken?: string): Promise<string[]> {
  if (!idToken) {
    throw new Error("User not authenticated")
  }
  const response = await fetch(`${config.BACKEND_URL}/api/get-watched-labels`, {
    headers: {
      Authorization: `Bearer ${idToken}`,
    },
  })
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: "Failed to get watched labels" }))
    throw new Error(errorData.message || response.statusText)
  }
  const data = await response.json()
  return (data.watchedLabelIds || []) as string[]
}

async function updateWatchedLabels(idToken: string, labelIds: string[]): Promise<void> {
  if (!idToken) {
    throw new Error("User not authenticated")
  }
  const response = await fetch(`${config.BACKEND_URL}/api/update-watched-labels`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${idToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ labelIds }),
  })
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: "Failed to update watched labels" }))
    throw new Error(errorData.message || response.statusText)
  }
}

async function stopCurrentWatch(idToken?: string): Promise<void> {
  if (!idToken) {
    throw new Error("User not authenticated")
  }
  const response = await fetch(`${config.BACKEND_URL}/api/stop-watch`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${idToken}`,
      "Content-Type": "application/json",
    },
  })
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ message: "Failed to stop watch" }))
    throw new Error(errorData.message || response.statusText)
  }
}

const Popup: React.FC = () => {
  const [sessionToken, setSessionToken] = useState<TokenResponse | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [authInProgress, setAuthInProgress] = useState<boolean>(false)

  // State for label management
  const [availableLabels, setAvailableLabels] = useState<Label[]>([])
  const [selectedLabels, setSelectedLabels] = useState<string[]>([])
  const [watchedLabels, setWatchedLabels] = useState<string[]>([])
  const [isFetchingLabels, setIsFetchingLabels] = useState<boolean>(false)
  const [isUpdatingLabels, setIsUpdatingLabels] = useState<boolean>(false)
  const [isStoppingWatch, setIsStoppingWatch] = useState<boolean>(false)

  // Settings state
  const [moveToTrash, setMoveToTrash] = useState<boolean>(true)
  const [isLoadingPreferences, setIsLoadingPreferences] = useState<boolean>(false)
  const [preferenceError, setPreferenceError] = useState<string | null>(null)

  // OTP display related
  const [otpResult, setOtpResult] = useState<OtpResult | null>(null)
  const [socket, setSocket] = useState<WebSocket | null>(null)

  // Fetch auth status and label info on load
  useEffect(() => {
    checkLoginStatusAndLoadData()
  }, [])

  // Combined function to check auth and load label data if authenticated
  const checkLoginStatusAndLoadData = useCallback(async () => {
    setIsLoading(true)
    setAuthInProgress(true)
    setError(null)
    let doLocalLogout = false
    try {
      const isAuthenticatedInitially = await oauthManager.isAuthenticated()
      const currentToken = await oauthManager.getTokenResponse();
      setSessionToken(currentToken);
      
      if (isAuthenticatedInitially && currentToken) {
        setIsFetchingLabels(true); // Start label fetching loading state
        // Reset preference error on load/re-auth
        setPreferenceError(null); 
        // Fetch labels and preferences concurrently
        try {
          const [fetchedAvailable, fetchedWatchedIds, prefsData] = await Promise.all([
            listLabels(currentToken.id_token),
            getWatchedLabels(currentToken.id_token),
            // Fetch preferences directly here if logged in
            fetch(`${config.BACKEND_URL}/api/get-user-preferences`, {
              headers: { Authorization: `Bearer ${currentToken.id_token}` },
            }).then(res => res.ok ? res.json() : Promise.reject(new Error(`Prefetch failed: ${res.status}`)))
          ]);
          
          const filteredAvailable = fetchedAvailable.filter((l: Label) => l.id === 'INBOX' || l.type === 'user')
          setAvailableLabels(filteredAvailable)
          setWatchedLabels(fetchedWatchedIds)
          setSelectedLabels(fetchedWatchedIds);
          // Set preference state from concurrent fetch
          setMoveToTrash(prefsData.moveToTrash ?? true); 
          
        } catch (fetchError: any) {
          console.error("Error fetching initial data:", fetchError.message)
          if (fetchError.message?.includes('User not authenticated') || fetchError.message?.includes('User token data not found') || fetchError.message?.includes('Prefetch failed')) {
            setError("Session expired or invalid. Please login again.")
            setSessionToken(null)
            doLocalLogout = true 
          } else {
            setError(`Failed to load initial data: ${fetchError.message}`)
          }
          setAvailableLabels([])
          setWatchedLabels([])
          setMoveToTrash(true); // Reset pref on error
        } finally {
          setIsFetchingLabels(false);
        }
      } else {
        setAvailableLabels([])
        setWatchedLabels([])
        setMoveToTrash(true);
        if (isAuthenticatedInitially && !currentToken) {
          console.warn("Auth check passed but no token response found. Forcing logout.")
          doLocalLogout = true;
        }
      }
    } catch (error: any) {
      console.error("Error checking login status/loading data:", error.message)
      setError("Failed to check login status")
      setAvailableLabels([])
      setWatchedLabels([])
      setMoveToTrash(true);
      doLocalLogout = true 
    } finally {
      setAuthInProgress(false)
      setIsLoading(false)
      if (doLocalLogout) {
        console.log("Performing local logout due to detected session invalidation.")
        setSessionToken(null)
        setMoveToTrash(true); // Reset preference state on logout
        await oauthManager.logout() 
      }
    }
  }, [])

  // Handler for login button
  const loginWithGoogle = async () => {
    setIsLoading(true)
    setError(null)
    setMessage(null)
    setAvailableLabels([])
    setWatchedLabels([])
    setMoveToTrash(true); // Reset on login attempt
    try {
      await oauthManager.login();
      console.log("Login successful, notifying background script to trigger its auth callbacks");
      chrome.runtime.sendMessage({ action: "authSucceededInPopup" }, (response) => {
        if (chrome.runtime.lastError) {
          console.warn("Failed to notify background script of successful auth:", chrome.runtime.lastError.message);
        } else {
          console.log("Background script notified of successful auth:", response);
        }
      });
      
      await checkLoginStatusAndLoadData(); 
    } catch (error: any) {
      console.error("Login initiation failed:", error.message)
      setError("Login failed: " + error.message);
    } finally {
      setIsLoading(false);
    }
  }

  // Handler for logout button
  const handleLogout = async () => {
    setIsLoading(true)
    setError(null)
    setMessage(null)
    try {
      await oauthManager.logout()
      setSessionToken(null)
      setAvailableLabels([])
      setWatchedLabels([])
      setMoveToTrash(true);
      setMessage("Logged out successfully");
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error("Logout failed:", error.message)
      setError(`Logout failed: ${error.message}`)
    } finally {
      setIsLoading(false)
    }
  }

  // Handler for label checkbox changes
  const handleLabelSelectionChange = (labelId: string, checked: boolean) => {
    setSelectedLabels(prev => {
      const newSet = new Set(prev)
      if (checked) {
        newSet.add(labelId)
      } else {
        newSet.delete(labelId)
      }
      return Array.from(newSet)
    })
  }

  // Handler for updating watched labels on the backend
  const handleUpdateWatch = async () => {
    setIsUpdatingLabels(true)
    setError(null)
    setMessage(null)
    try {
      const labelsToWatch = selectedLabels
      await updateWatchedLabels(sessionToken!.id_token!, labelsToWatch)
      const updatedWatched = await getWatchedLabels(sessionToken!.id_token!)
      setWatchedLabels(updatedWatched)
      setMessage("Watched labels updated!");
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error("Failed to update watched labels:", error.message)
      setError(`Failed to update labels: ${error.message}`)
    } finally {
      setIsUpdatingLabels(false)
    }
  }

  // New handler for stopping all watches
  const handleStopAllWatching = async () => {
    setIsStoppingWatch(true)
    setError(null)
    setMessage(null)
    try {
      await stopCurrentWatch(sessionToken!.id_token!)
      setWatchedLabels([])
      setMessage("Gmail watch stopped.");
      setTimeout(() => setMessage(null), 3000);
    } catch (error: any) {
      console.error("Failed to stop watch:", error.message)
      setError(`Failed to stop watch: ${error.message}`)
    } finally {
      setIsStoppingWatch(false)
    }
  }

  // Handler for changing the "Move to Trash" preference
  const handleMoveToTrashToggle = async (newMoveToTrashState: boolean) => {
    if (!sessionToken || !sessionToken.id_token) { 
      setMessage("Please log in to change this setting.");
      return;
    }
    
    // Set loading state for this specific action
    setIsLoadingPreferences(true); 
    setMoveToTrash(newMoveToTrashState); 
    setMessage(null); // Clear general messages
    setPreferenceError(null);

    try {
      const backendUrl = config.BACKEND_URL; 
      const idToken = sessionToken.id_token;

      const response = await fetch(`${backendUrl}/api/update-trash-preference`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${idToken}`,
        },
        body: JSON.stringify({ moveToTrash: newMoveToTrashState }),
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        setMoveToTrash(!newMoveToTrashState); 
        setPreferenceError(result.message || "Failed to update preference.");
        console.error("Error updating trash preference:", result);
      } else {
        setMessage(result.message || "Preference updated!");
        setTimeout(() => setMessage(null), 3000);
      }
    } catch (err: any) {
      setMoveToTrash(!newMoveToTrashState); 
      setPreferenceError(err.message || "An error occurred.");
      console.error("Error calling update-trash-preference API:", err);
    } finally {
        setIsLoadingPreferences(false); // Clear loading state
    }
  };

  if (isLoading) {
    return <div className="popup-container p-6 w-[350px] font-sans text-center text-gray-500"><p>Loading...</p></div>;
  }

  return (
    <div className="popup-container p-5 w-[350px] font-sans text-gray-800 bg-gray-50 flex flex-col space-y-4 max-h-[580px] overflow-y-auto">
      <h3 className="text-center text-base font-semibold text-gray-600 uppercase tracking-wider">Quick OTP</h3>

      <div className="status-area space-y-2">
        {error && <p className="text-xs text-red-600 border border-red-200 bg-red-50 p-2 rounded-md">Error: {error}</p>}
        {message && <p className="text-xs text-green-700 border border-green-200 bg-green-50 p-2 rounded-md">{message}</p>}
      </div>

      {!sessionToken ? (
        <div className="flex justify-center items-center h-full pt-10">
          <Button onClick={loginWithGoogle} className="w-3/4" disabled={authInProgress}>
            {authInProgress ? "Logging in..." : "Login with Google"}
          </Button>
        </div>
      ) : (
        <div className="flex flex-col space-y-5">
          
          {otpResult && (
            <div className="otp-display border border-blue-100 bg-blue-50 p-3 rounded-md shadow-sm text-center">
              <p className="text-sm font-medium text-blue-700 mb-1">Last Received OTP</p>
              {otpResult.code && <p className="text-2xl font-mono text-blue-900 tracking-widest">{otpResult.code}</p>}
            </div>
          )}
          
          <div className="label-section space-y-3">
            <h4 className="text-sm font-semibold text-gray-700">Watch Labels</h4>
            <div className="text-xs text-gray-500"><span className="font-medium">Active:</span> { 
                isFetchingLabels ? "(loading...)" :
                watchedLabels.length > 0 ? 
                  watchedLabels.map(id => availableLabels.find(l => l.id === id)?.name || id).join(', ') :
                  <span className="italic">None</span>
              }
            </div>
            {isFetchingLabels ? (
              <p className="text-xs text-gray-400">(Loading labels...)</p>
            ) : availableLabels.length > 0 ? (
              <div className="max-h-[120px] overflow-y-auto space-y-2 border border-gray-200 p-3 rounded bg-white">
                {availableLabels.map((label) => (
                  <div key={label.id} className="flex items-center space-x-2">
                    <Checkbox 
                      id={label.id}
                      checked={selectedLabels.includes(label.id)}
                      onCheckedChange={(checkedState: boolean) => handleLabelSelectionChange(label.id, checkedState)}
                      aria-labelledby={`label-${label.id}`}
                    />
                    <UILabel htmlFor={label.id} id={`label-${label.id}`} className="text-xs font-medium text-gray-700 cursor-pointer">
                      {label.name}
                    </UILabel>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">(No labels found or failed.)</p>
            )}
            <div className="flex space-x-2">
              {availableLabels.length > 0 && (
                <Button 
                  type="button"
                  size="sm"
                  variant="secondary"
                  className="flex-grow"
                  onClick={handleUpdateWatch}
                  disabled={isUpdatingLabels || isFetchingLabels || isStoppingWatch || selectedLabels.length === 0}
                >
                  {isUpdatingLabels ? "Updating..." : "Update Watch"}
                </Button>
              )}
              {watchedLabels.length > 0 && (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className="text-red-600 hover:bg-red-50 hover:text-red-700 flex-shrink-0"
                  onClick={handleStopAllWatching}
                  disabled={isStoppingWatch || isUpdatingLabels || isFetchingLabels}
                >
                  {isStoppingWatch ? "Stopping..." : "Stop Watch"}
                </Button>
              )}
            </div>
          </div>

          <div className="settings-area border-t border-gray-200 pt-4 space-y-3">
             <h4 className="text-sm font-semibold text-gray-700">Settings</h4>
             <div className="flex items-center justify-between space-x-2">
               <UILabel htmlFor="moveToTrashToggle" className="text-xs font-medium text-gray-700 flex-grow cursor-pointer">
                 Automatically move OTP emails to Trash
               </UILabel>
               <Switch 
                 id="moveToTrashToggle"
                 checked={moveToTrash}
                 onCheckedChange={handleMoveToTrashToggle}
                 disabled={isLoadingPreferences || !sessionToken}
                 aria-label="Automatically move OTP emails to Trash"
               />
               {isLoadingPreferences && <span className="text-xs text-gray-500">(...)</span>}
             </div>
             {preferenceError && <p className="text-xs text-red-600">Error: {preferenceError}</p>}
             
             <Button 
                onClick={handleLogout} 
                variant="outline" 
                size="sm" 
                className="w-full text-gray-700 hover:bg-gray-100"
                disabled={isLoading}
              >
               Logout ({sessionToken.email ? sessionToken.email.split('@')[0] : 'User'})
             </Button>
          </div>
          
        </div>
      )}
    </div>
  );
};

export default Popup

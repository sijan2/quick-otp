import React, { useState, useEffect, useCallback } from "react"
import { oauthManager } from "../lib/oauth"
import { Button, buttonVariants } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import {  GmailLabel, listLabels, getWatchedLabels, updateWatchedLabels, stopCurrentWatch } from "@/lib/setup"

const Popup: React.FC = () => {
  const [session, setSession] = useState<boolean>(false)
  const [isLoading, setIsLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [authInProgress, setAuthInProgress] = useState<boolean>(false)

  // State for label management
  const [availableLabels, setAvailableLabels] = useState<GmailLabel[]>([])
  const [watchedLabelIds, setWatchedLabelIds] = useState<Set<string>>(new Set())
  const [isLoadingLabels, setIsLoadingLabels] = useState<boolean>(false)
  const [isUpdatingLabels, setIsUpdatingLabels] = useState<boolean>(false)
  const [isStoppingWatch, setIsStoppingWatch] = useState<boolean>(false)

  // Fetch auth status and label info on load
  useEffect(() => {
    checkLoginStatusAndLoadData()
  }, [])

  // Combined function to check auth and load label data if authenticated
  const checkLoginStatusAndLoadData = useCallback(async () => {
    setIsLoadingLabels(true)
    setAuthInProgress(true)
    setError(null)
    let doLocalLogout = false
    try {
      const isAuthenticatedInitially = await oauthManager.isAuthenticated()
      // Optimistically set session, but verify with API calls
      setSession(isAuthenticatedInitially)
      
      if (isAuthenticatedInitially) {
        try {
          const [fetchedAvailable, fetchedWatchedIds] = await Promise.all([
            listLabels(),
            getWatchedLabels()
          ])
          const filteredAvailable = fetchedAvailable.filter(l => l.id === 'INBOX' || l.type === 'user')
          setAvailableLabels(filteredAvailable)
          setWatchedLabelIds(new Set(fetchedWatchedIds))
        } catch (labelError: any) {
          console.error("Error fetching label data:", labelError.message)
          if (labelError.message?.includes('User not authenticated') || labelError.message?.includes('User token data not found')) {
            // This indicates backend session is invalid or tokens are gone
            setError("Session expired or logged out from another device. Please login again.")
            setSession(false); // Immediately update session state to reflect logout
            doLocalLogout = true // Mark for local logout
          } else {
            setError(`Failed to load label preferences: ${labelError.message}`)
          }
          setAvailableLabels([])
          setWatchedLabelIds(new Set())
        }
      } else {
        setAvailableLabels([])
        setWatchedLabelIds(new Set())
      }
    } catch (error: any) {
      console.error("Error checking login status/loading data:", error.message)
      setError("Failed to check login status")
      setAvailableLabels([])
      setWatchedLabelIds(new Set())
      doLocalLogout = true // If initial isAuthenticated fails, also logout locally to be sure
    } finally {
      setAuthInProgress(false)
      setIsLoadingLabels(false)
      if (doLocalLogout) {
        console.log("Performing local logout due to detected session invalidation.")
        setSession(false) // Immediately update UI
        await oauthManager.logout() // Ensure local tokens are cleared properly
        // No need to call checkLoginStatusAndLoadData again here, UI will reflect logged out state.
      }
    }
  }, []) // useCallback dependencies are empty as it reads state via setters mostly

  // Handler for login button
  const loginWithGoogle = async () => {
    setIsLoading(true)
    setError(null)
    setMessage(null)
    setAvailableLabels([]) // Clear labels before login attempt
    setWatchedLabelIds(new Set())
    try {
      // Send message to background to trigger login
      chrome.runtime.sendMessage({ action: 'loginManually' }, (response) => {
        if (chrome.runtime.lastError) {
          console.error("Error sending login message:", chrome.runtime.lastError.message)
          setError("Failed to start login process")
          setIsLoading(false)
          return
        }
        // setMessage("Authentication window opened..."); // User will see this anyway
        setTimeout(() => {
          checkLoginStatusAndLoadData() // Re-check auth and load labels
          setIsLoading(false)
        }, 7000) // Increased delay slightly
      })
    } catch (error: any) {
      console.error("Login initiation failed:", error.message)
      setError("Login initiation failed")
      setIsLoading(false)
    }
  }

  // Handler for logout button
  const handleLogout = async () => {
    setIsLoading(true)
    setError(null)
    setMessage(null)
    try {
      await oauthManager.logout() // This now calls backend logout too
      setSession(false)
      // Clear label states on logout
      setAvailableLabels([])
      setWatchedLabelIds(new Set())
      // setMessage("Logged out successfully") // UI updates are enough
    } catch (error: any) {
      console.error("Logout failed:", error.message)
      setError(`Logout failed: ${error.message}`)
    } finally {
      setIsLoading(false)
    }
  }

  // Handler for label checkbox changes
  const handleLabelSelectionChange = (labelId: string, checked: boolean) => {
    setWatchedLabelIds(prev => {
      const newSet = new Set(prev)
      if (checked) {
        newSet.add(labelId)
      } else {
        newSet.delete(labelId)
      }
      return newSet
    })
  }

  // Handler for updating watched labels on the backend
  const handleUpdateWatch = async () => {
    setIsUpdatingLabels(true)
    setError(null)
    setMessage(null)
    try {
      const labelsToWatch = Array.from(watchedLabelIds)
      if (labelsToWatch.length === 0) {
        // Maybe enforce at least one label? Or let backend handle empty list?
        // For now, let backend decide. Backend watch setup might fail with empty list.
         // console.warn("Attempting to update watch with zero labels selected.")
      }
      
      await updateWatchedLabels(labelsToWatch)
      // setMessage("Watched labels updated successfully!") // Can rely on UI update
      // Re-fetch watched labels to update the display accurately
      try {
        const updatedWatched = await getWatchedLabels()
        setWatchedLabelIds(new Set(updatedWatched))
      } catch (fetchError: any) { /* console.error already in checkLoginStatusAndLoadData or here */ }
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
      await stopCurrentWatch()
      setWatchedLabelIds(new Set()) // Clear local state
      // setMessage("Gmail watch stopped successfully.") // Can rely on UI update
    } catch (error: any) {
      console.error("Failed to stop watch:", error.message)
      setError(`Failed to stop watch: ${error.message}`)
    } finally {
      setIsStoppingWatch(false)
    }
  }

  // Remove unused handlers/state related to old watch logic
  // const handleRevokeAccessToken = ... 
  // REMOVE testWebSocketConnection handler if it exists and is only for the button
  // const testWebSocketConnection = () => { ... }

  return (
    <div className="flex flex-col w-[350px] rounded bg-slate-50 p-4 space-y-3">
      <h2 className="text-lg font-semibold text-center">OTP Extension</h2>
      
      <div className="bg-gray-100 p-3 rounded">
        <span className="font-medium">Status: </span>
        <span className={session ? "text-green-600" : "text-amber-600"}>
          {authInProgress 
            ? "Checking..."
            : session 
            ? "Authenticated" 
            : "Not authenticated"}
        </span>
      </div>
      
      {/* Login/Logout Button - Changed to default variant for better contrast */}
      <Button
        type="button"
        className={cn(buttonVariants({ variant: "default" }))}
        onClick={session ? handleLogout : loginWithGoogle}
        disabled={isLoading || authInProgress}
      >
        {isLoading
          ? "Processing..."
          : session
          ? "Logout"
          : "Login with Google"}
      </Button>

      {/* Label Selection Section - Only show if logged in */} 
      {session && (
        <div className="border-t pt-3 mt-3 space-y-2">
          <h3 className="text-md font-semibold">Watch Labels:</h3>
          {/* Display currently watched labels */}
          <div className="text-xs text-gray-600 mb-2 px-1">
            Currently Watching: {
              isLoadingLabels ? "(loading...)" :
              watchedLabelIds.size > 0 ? 
                Array.from(watchedLabelIds).map(id => availableLabels.find(l => l.id === id)?.name || id).join(', ') :
                "None"
            }
          </div>

          {isLoadingLabels ? (
            <p className="text-gray-500">Loading labels...</p>
          ) : availableLabels.length > 0 ? (
            <div className="max-h-32 overflow-y-auto space-y-1 border p-2 rounded bg-white">
              {availableLabels.map((label) => (
                <div key={label.id} className="flex items-center space-x-2">
                  <input 
                    type="checkbox"
                    id={label.id}
                    value={label.id}
                    checked={watchedLabelIds.has(label.id)}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => handleLabelSelectionChange(label.id, e.target.checked)}
                    className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  <label htmlFor={label.id} className="text-sm font-medium text-gray-700">
                    {label.name} {label.id === 'INBOX' ? '(Recommended)' : ''}
                  </label>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500">No labels found or failed to load.</p>
          )}

          {/* Update Watch Button - Text changes based on if any labels are selected to watch */} 
          {availableLabels.length > 0 && (
              <Button 
                type="button"
                className={cn(buttonVariants({ variant: "secondary" }), "w-full")}
                onClick={handleUpdateWatch}
                disabled={isUpdatingLabels || isLoadingLabels || isStoppingWatch}
              >
                {isUpdatingLabels ? "Updating..." : (watchedLabelIds.size > 0) ? "Update Watched Labels" : "Start Watching Selected"}
              </Button>
          )}

          {/* Stop All Watching Button - Only show if currently watching something */} 
          {watchedLabelIds.size > 0 && (
            <Button
              type="button"
              variant="destructive"
              className={cn("w-full mt-2", buttonVariants({variant: "destructive"}))} 
              onClick={handleStopAllWatching}
              disabled={isStoppingWatch || isUpdatingLabels || isLoadingLabels}
            >
              {isStoppingWatch ? "Stopping..." : "Stop All Watching"}
            </Button>
          )}
        </div>
      )}
      
      {/* Error and Message Display */} 
      {error && <div className="text-red-500 mt-2 p-2 text-sm bg-red-50 rounded">Error: {error}</div>}
      {message && <div className="text-green-600 mt-2 p-2 text-sm bg-green-50 rounded">{message}</div>}

      
       
    </div>
  )
}

export default Popup

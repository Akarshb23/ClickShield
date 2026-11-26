import React, { useEffect, useRef, useState } from "react";

import {

  Shield,

  Bell,

  Sliders,

  Check,

  RotateCcw,

} from "lucide-react";

import type { ClickShieldSettings } from "../shared/types/settings";

import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";

type SaveStatus = "idle" | "saving" | "saved" | "error";

function isValidSettings(value: unknown): value is ClickShieldSettings {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Record<string, unknown>;

  return (
    typeof candidate.protectionEnabled === "boolean" &&
    typeof candidate.clipboardProtection === "boolean" &&
    typeof candidate.notificationsEnabled === "boolean" &&
    (candidate.detectionSensitivity === "low" ||
      candidate.detectionSensitivity === "balanced" ||
      candidate.detectionSensitivity === "aggressive")
  );
}

export default function OptionsApp() {

  const [settings, setSettings] =

    useState<ClickShieldSettings>(DEFAULT_SETTINGS);

  const [isLoading, setIsLoading] = useState(true);
  const [settingsLoaded, setSettingsLoaded] = useState(false);

  const [saveStatus, setSaveStatus] = useState<SaveStatus>("idle");

  const [error, setError] = useState("");

  const savingRef = useRef(false);

  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {

    void loadSettings();

    return () => {

      if (savedTimerRef.current) {

        clearTimeout(savedTimerRef.current);

      }

    };

  }, []);

  const loadSettings = async () => {

    setIsLoading(true);

    setError("");

    try {

      const response = await chrome.runtime.sendMessage({

        type: "GET_SETTINGS",

      });

      if (response?.error) {

        throw new Error(response.error);

      }

      if (!isValidSettings(response?.settings)) {
        throw new Error("The background service returned invalid settings.");
      }

      setSettings(response.settings);
      setSettingsLoaded(true);

    } catch (err) {

      console.error("Could not load ClickShield settings:", err);

      setSettingsLoaded(false);
      setError(
        err instanceof Error
          ? err.message
          : "Could not load settings. Please try again."
      );

    } finally {

      setIsLoading(false);

    }

  };

  const handleUpdate = async (

    patch: Partial<ClickShieldSettings>

  ) => {

    // Prevent overlapping settings updates.

    if (savingRef.current) {

      return;

    }

    savingRef.current = true;

    if (savedTimerRef.current) {

      clearTimeout(savedTimerRef.current);

      savedTimerRef.current = null;

    }

    setSaveStatus("saving");

    setError("");

    try {

      const response = await chrome.runtime.sendMessage({

        type: "UPDATE_SETTINGS",

        payload: patch,

      });

      if (response?.error) {

        throw new Error(response.error);

      }

      if (!isValidSettings(response?.settings)) {
        throw new Error("The background service did not confirm valid settings.");
      }

      // Update the interface only after storage confirms the change.

      setSettings(response.settings);

      setSaveStatus("saved");

      savedTimerRef.current = setTimeout(() => {

        setSaveStatus("idle");

        savedTimerRef.current = null;

      }, 2000);

    } catch (err) {

      console.error("Could not update ClickShield settings:", err);

      setSaveStatus("error");

      setError(

        err instanceof Error

          ? err.message

          : "Failed to save settings. Please try again."

      );

    } finally {

      savingRef.current = false;

    }

  };

  const handleReset = async () => {

    if (savingRef.current) {

      return;

    }

    const confirmed = window.confirm(

      "Reset all settings to default values?"

    );

    if (!confirmed) {

      return;

    }

    await handleUpdate(DEFAULT_SETTINGS);

  };

  const handleDashboard = async () => {

    setError("");

    try {

      await chrome.tabs.create({

        url: chrome.runtime.getURL("src/dashboard/index.html"),

      });

    } catch (err) {

      console.error("Could not open dashboard:", err);

      setError("Could not open the dashboard.");

    }

  };

  const isSaving = saveStatus === "saving";

  const controlsDisabled = isLoading || isSaving || !settingsLoaded;

  return (

    <div className="max-w-3xl mx-auto p-10 font-sans">

      {/* Header */}

      <header className="flex items-center justify-between pb-6 border-b border-[#222222] mb-8">

        <div className="flex items-center gap-3">

          <div className="w-9 h-9 rounded bg-[#171717] border border-[#E5B83B]/50 flex items-center justify-center">

            <Shield className="w-5 h-5 text-[#E5B83B]" />

          </div>

          <div>

            <h1 className="text-xl font-bold font-mono tracking-tight text-neutral-100">

              ClickShield Preferences

            </h1>

            <p className="text-xs font-mono text-neutral-400">

              Configure detection thresholds and behavioral guard parameters

            </p>

          </div>

        </div>

        <div className="text-xs font-mono">

          {saveStatus === "saving" && (

            <span className="text-neutral-400">

              Saving...

            </span>

          )}

          {saveStatus === "saved" && (

            <span className="flex items-center gap-1 text-[#16A34A] bg-[#16A34A]/10 px-3 py-1 rounded border border-[#16A34A]/30">

              <Check className="w-3.5 h-3.5" />

              Saved

            </span>

          )}

          {saveStatus === "error" && (

            <span className="text-red-400">

              Save failed

            </span>

          )}

        </div>

      </header>

      {/* Loading State */}

      {isLoading ? (

        <div className="py-12 text-center text-sm font-mono text-neutral-400">

          Loading preferences...

        </div>

      ) : !settingsLoaded ? (
        <div className="py-12 text-center">
          <p className="text-sm font-mono text-red-400 mb-4" role="alert">
            {error || "Settings could not be loaded."}
          </p>
          <button
            type="button"
            onClick={loadSettings}
            className="px-4 py-2 bg-[#1A1A1A] hover:bg-[#222222] border border-[#2E2E2E] rounded text-xs font-mono text-[#E5B83B] cursor-pointer"
          >
            Retry Loading Settings
          </button>
        </div>
      ) : (

        <div className="space-y-6">

          {/* Core Protection Engine */}

          <div className="p-5 rounded bg-[#111111] border border-[#222222]">

            <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider mb-4 flex items-center gap-2">

              <Shield className="w-4 h-4 text-[#E5B83B]" />

              Core Protection Engine

            </h2>

            <div className="space-y-4">

              {/* Page Inspection */}

              <label className="flex items-center justify-between cursor-pointer">

                <div>

                  <div className="text-xs font-mono font-medium text-neutral-200">

                    Real-Time Page Behavioral Inspection

                  </div>

                  <div className="text-[11px] text-neutral-500 font-mono mt-0.5">

                    Continuously scans webpage DOM for fake CAPTCHA prompts

                    and deceptive commands.

                  </div>

                </div>

                <input

                  type="checkbox"

                  checked={settings.protectionEnabled}

                  disabled={controlsDisabled}

                  onChange={(e) =>

                    handleUpdate({

                      protectionEnabled: e.target.checked,

                    })

                  }

                  className="w-4 h-4 accent-[#E5B83B] cursor-pointer disabled:opacity-40"

                />

              </label>

              {/* Clipboard Protection */}

              <label className="flex items-center justify-between cursor-pointer pt-3 border-t border-[#1C1C1C]">

                <div>

                  <div className="text-xs font-mono font-medium text-neutral-200">

                    Clipboard Interception Guard

                  </div>

                  <div className="text-[11px] text-neutral-500 font-mono mt-0.5">

                    Flags suspicious copy commands correlated with fake

                    verification dialogs.

                  </div>

                </div>

                <input

                  type="checkbox"

                  checked={settings.clipboardProtection}

                  disabled={controlsDisabled}

                  onChange={(e) =>

                    handleUpdate({

                      clipboardProtection: e.target.checked,

                    })

                  }

                  className="w-4 h-4 accent-[#E5B83B] cursor-pointer disabled:opacity-40"

                />

              </label>

            </div>

          </div>

          {/* Alerts and Notifications */}

          <div className="p-5 rounded bg-[#111111] border border-[#222222]">

            <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider mb-4 flex items-center gap-2">

              <Bell className="w-4 h-4 text-[#E5B83B]" />

              Alerts & Notifications

            </h2>

            <label className="flex items-center justify-between cursor-pointer">

              <div>

                <div className="text-xs font-mono font-medium text-neutral-200">

                  Desktop System Notifications

                </div>

                <div className="text-[11px] text-neutral-500 font-mono mt-0.5">

                  Displays system notification alerts when critical ClickFix

                  attack vectors are identified.

                </div>

              </div>

              <input

                type="checkbox"

                checked={settings.notificationsEnabled}

                disabled={controlsDisabled}

                onChange={(e) =>

                  handleUpdate({

                    notificationsEnabled: e.target.checked,

                  })

                }

                className="w-4 h-4 accent-[#E5B83B] cursor-pointer disabled:opacity-40"

              />

            </label>

          </div>

          {/* Detection Sensitivity */}

          <div className="p-5 rounded bg-[#111111] border border-[#222222]">

            <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider mb-4 flex items-center gap-2">

              <Sliders className="w-4 h-4 text-[#E5B83B]" />

              Heuristic Calibration

            </h2>

            <div className="space-y-3">

              <div className="text-xs font-mono font-medium text-neutral-300">

                Detection Sensitivity

              </div>

              <div className="grid grid-cols-3 gap-3">

                {(["low", "balanced", "aggressive"] as const).map(

                  (mode) => (

                    <button

                      key={mode}

                      type="button"

                      disabled={controlsDisabled}

                      onClick={() =>

                        handleUpdate({

                          detectionSensitivity: mode,

                        })

                      }

                      className={`py-2 px-3 rounded font-mono text-xs uppercase border cursor-pointer transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${settings.detectionSensitivity === mode

                          ? "border-[#E5B83B] bg-[#E5B83B]/10 text-[#E5B83B] font-bold"

                          : "border-[#262626] bg-[#161616] text-neutral-400 hover:text-neutral-200"

                        }`}

                    >

                      {mode}

                    </button>

                  )

                )}

              </div>

              <div className="text-[10px] text-neutral-500 font-mono">

                Balanced is recommended for minimal false positives while

                catching active ClickFix attacks.

              </div>

            </div>

          </div>

          {/* Error Message */}

          {error && (

            <div

              role="alert"

              className="p-3 rounded border border-red-500/30 bg-red-500/10 text-xs font-mono text-red-400"

            >

              {error}

            </div>

          )}

          {/* Footer Actions */}

          <div className="flex items-center justify-between pt-4">

            <button

              type="button"

              onClick={handleReset}

              disabled={controlsDisabled}

              className="flex items-center gap-1.5 text-xs font-mono text-neutral-400 hover:text-neutral-200 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"

            >

              <RotateCcw className="w-3.5 h-3.5" />

              Reset to Defaults

            </button>

            <button

              type="button"

              onClick={handleDashboard}

              className="px-4 py-2 bg-[#1A1A1A] hover:bg-[#222222] border border-[#2E2E2E] rounded text-xs font-mono text-[#E5B83B] cursor-pointer"

            >

              Open Dashboard →

            </button>

          </div>

        </div>

      )}

    </div>

  );

}
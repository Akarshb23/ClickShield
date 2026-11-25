import React, { useEffect, useState } from "react";
import { Shield, Bell, Copy, Sliders, Check, RotateCcw } from "lucide-react";
import type { ClickShieldSettings } from "../shared/types/settings";
import { DEFAULT_SETTINGS } from "../shared/constants/default-settings";

export default function OptionsApp() {
  const [settings, setSettings] = useState<ClickShieldSettings>(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const res = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
      if (res?.settings) {
        setSettings(res.settings);
      }
    } catch (e) {
      console.debug("Could not load settings:", e);
    }
  };

  const handleUpdate = async (patch: Partial<ClickShieldSettings>) => {
    const updated = { ...settings, ...patch };
    setSettings(updated);
    await chrome.runtime.sendMessage({
      type: "UPDATE_SETTINGS",
      payload: patch,
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleReset = async () => {
    if (confirm("Reset all settings to default values?")) {
      await handleUpdate(DEFAULT_SETTINGS);
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-10 font-sans">
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

        {saved && (
          <span className="flex items-center gap-1 text-xs font-mono text-[#16A34A] bg-[#16A34A]/10 px-3 py-1 rounded border border-[#16A34A]/30">
            <Check className="w-3.5 h-3.5" /> Saved
          </span>
        )}
      </header>

      <div className="space-y-6">
        {/* Protection Module */}
        <div className="p-5 rounded bg-[#111111] border border-[#222222]">
          <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#E5B83B]" /> Core Protection Engine
          </h2>

          <div className="space-y-4">
            <label className="flex items-center justify-between cursor-pointer">
              <div>
                <div className="text-xs font-mono font-medium text-neutral-200">
                  Real-Time Page Behavioral Inspection
                </div>
                <div className="text-[11px] text-neutral-500 font-mono mt-0.5">
                  Continuously scans webpage DOM for fake CAPTCHA prompts and deceptive commands.
                </div>
              </div>
              <input
                type="checkbox"
                checked={settings.protectionEnabled}
                onChange={(e) => handleUpdate({ protectionEnabled: e.target.checked })}
                className="w-4 h-4 accent-[#E5B83B] cursor-pointer"
              />
            </label>

            <label className="flex items-center justify-between cursor-pointer pt-3 border-t border-[#1C1C1C]">
              <div>
                <div className="text-xs font-mono font-medium text-neutral-200">
                  Clipboard Interception Guard
                </div>
                <div className="text-[11px] text-neutral-500 font-mono mt-0.5">
                  Flags suspicious copy commands correlated with fake verification dialogs.
                </div>
              </div>
              <input
                type="checkbox"
                checked={settings.clipboardProtection}
                onChange={(e) => handleUpdate({ clipboardProtection: e.target.checked })}
                className="w-4 h-4 accent-[#E5B83B] cursor-pointer"
              />
            </label>
          </div>
        </div>

        {/* Alerts & Notifications */}
        <div className="p-5 rounded bg-[#111111] border border-[#222222]">
          <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Bell className="w-4 h-4 text-[#E5B83B]" /> Alerts & Notifications
          </h2>

          <label className="flex items-center justify-between cursor-pointer">
            <div>
              <div className="text-xs font-mono font-medium text-neutral-200">
                Desktop System Notifications
              </div>
              <div className="text-[11px] text-neutral-500 font-mono mt-0.5">
                Displays system notification alerts when critical ClickFix attack vectors are identified.
              </div>
            </div>
            <input
              type="checkbox"
              checked={settings.notificationsEnabled}
              onChange={(e) => handleUpdate({ notificationsEnabled: e.target.checked })}
              className="w-4 h-4 accent-[#E5B83B] cursor-pointer"
            />
          </label>
        </div>

        {/* Sensitivity */}
        <div className="p-5 rounded bg-[#111111] border border-[#222222]">
          <h2 className="text-sm font-bold font-mono text-neutral-200 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Sliders className="w-4 h-4 text-[#E5B83B]" /> Heuristic Calibration
          </h2>

          <div className="space-y-3">
            <div className="text-xs font-mono font-medium text-neutral-300">
              Detection Sensitivity
            </div>
            <div className="grid grid-cols-3 gap-3">
              {(["low", "balanced", "aggressive"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => handleUpdate({ detectionSensitivity: mode })}
                  className={`py-2 px-3 rounded font-mono text-xs uppercase border cursor-pointer transition-colors ${
                    settings.detectionSensitivity === mode
                      ? "border-[#E5B83B] bg-[#E5B83B]/10 text-[#E5B83B] font-bold"
                      : "border-[#262626] bg-[#161616] text-neutral-400 hover:text-neutral-200"
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
            <div className="text-[10px] text-neutral-500 font-mono">
              Balanced is recommended for minimal false positives while catching active ClickFix attacks.
            </div>
          </div>
        </div>

        {/* Reset */}
        <div className="flex items-center justify-between pt-4">
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 text-xs font-mono text-neutral-400 hover:text-neutral-200 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Reset to Defaults
          </button>

          <button
            onClick={() => chrome.tabs.create({ url: chrome.runtime.getURL("src/dashboard/index.html") })}
            className="px-4 py-2 bg-[#1A1A1A] hover:bg-[#222222] border border-[#2E2E2E] rounded text-xs font-mono text-[#E5B83B] cursor-pointer"
          >
            Open Dashboard →
          </button>
        </div>
      </div>
    </div>
  );
}


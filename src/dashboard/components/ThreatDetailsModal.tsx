import React from "react";
import { X, ShieldAlert, AlertTriangle, ExternalLink } from "lucide-react";
import type { ThreatRecord } from "../../shared/types/threat";

interface ThreatDetailsModalProps {
  threat: ThreatRecord | null;
  onClose: () => void;
  onAllowlist: (hostname: string) => void;
}

export const ThreatDetailsModal: React.FC<ThreatDetailsModalProps> = ({
  threat,
  onClose,
  onAllowlist,
}) => {
  if (!threat) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 font-mono">
      <div className="w-full max-w-lg rounded-lg bg-[#111111] border border-[#2D2D2D] p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-neutral-400 hover:text-white cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="w-5 h-5 text-[#E5B83B]" />
          <h3 className="text-base font-bold text-neutral-100 uppercase tracking-wider">
            Threat Analysis Record
          </h3>
        </div>

        <div className="space-y-4 text-xs">
          <div>
            <div className="text-[10px] text-neutral-500 uppercase tracking-widest">Target Hostname</div>
            <div className="text-sm font-semibold text-neutral-200 mt-0.5">{threat.hostname}</div>
            <div className="text-[11px] text-neutral-500 truncate mt-0.5" title={threat.url}>
              {threat.url}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 p-3 bg-[#171717] rounded border border-[#262626]">
            <div>
              <div className="text-[10px] text-neutral-500 uppercase">Risk Evaluation</div>
              <div className="text-base font-black text-[#E5B83B] mt-0.5">{threat.riskScore} / 100</div>
              <span className="text-[10px] text-neutral-400 font-bold">{threat.riskLevel}</span>
            </div>
            <div>
              <div className="text-[10px] text-neutral-500 uppercase">Action Taken</div>
              <div className="text-sm font-semibold text-neutral-200 mt-0.5">{threat.action}</div>
              <span className="text-[10px] text-neutral-500">
                {new Date(threat.timestamp).toLocaleString()}
              </span>
            </div>
          </div>

          <div>
            <div className="text-[10px] text-neutral-500 uppercase tracking-widest mb-1.5">
              Detected Threat Vectors
            </div>
            <div className="space-y-1.5 max-h-36 overflow-y-auto">
              {threat.signals.map((sig, idx) => (
                <div
                  key={idx}
                  className="p-2 rounded bg-[#161616] border border-[#242424] text-neutral-300"
                >
                  <div className="font-bold text-[#E5B83B] text-[11px]">
                    {sig.replace(/_/g, " ")}
                  </div>
                  {threat.details && threat.details[idx] && (
                    <div className="text-[10px] text-neutral-400 mt-0.5 leading-relaxed">
                      {threat.details[idx]}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="pt-3 border-t border-[#222222] flex justify-end gap-2">
            <button
              onClick={() => {
                onAllowlist(threat.hostname);
                onClose();
              }}
              className="px-3 py-1.5 rounded bg-[#1C1C1C] hover:bg-[#252525] border border-[#333] text-neutral-200 font-medium cursor-pointer"
            >
              Add Domain to Allowlist
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded bg-[#E5B83B] hover:bg-[#F5CB5C] text-black font-bold cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};


import React, { useEffect, useRef } from "react";
import { X, ShieldAlert } from "lucide-react";
import type { ThreatRecord } from "../../shared/types/threat";

interface ThreatDetailsModalProps {
  threat: ThreatRecord | null;
  onClose: () => void;
  onAllowlist: (hostname: string) => void;
}

function getRiskStyles(riskLevel: ThreatRecord["riskLevel"]): string {
  switch (riskLevel) {
    case "CRITICAL":
      return "border-[#DC2626]/40 bg-[#DC2626]/10 text-[#F87171]";
    case "HIGH":
      return "border-[#EA580C]/40 bg-[#EA580C]/10 text-[#FB923C]";
    case "SUSPICIOUS":
      return "border-[#D4A32C]/40 bg-[#D4A32C]/10 text-[#FDE047]";
    default:
      return "border-[#404040] bg-[#262626]/50 text-neutral-300";
  }
}

function formatTimestamp(timestamp: ThreatRecord["timestamp"]): string {
  const date = new Date(timestamp);

  return Number.isNaN(date.getTime())
    ? "Unknown timestamp"
    : date.toLocaleString();
}

export const ThreatDetailsModal: React.FC<ThreatDetailsModalProps> = ({
  threat,
  onClose,
  onAllowlist,
}) => {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const threatId = threat?.id;

  useEffect(() => {
    if (!threatId) return;

    const previouslyFocused = document.activeElement as HTMLElement | null;
    const previousBodyOverflow = document.body.style.overflow;

    document.body.style.overflow = "hidden";
    closeButtonRef.current?.focus();

    return () => {
      document.body.style.overflow = previousBodyOverflow;
      previouslyFocused?.focus?.();
    };
  }, [threatId]);

  if (!threat) return null;

  const riskScore = Number.isFinite(threat.riskScore)
    ? Math.min(100, Math.max(0, threat.riskScore))
    : 0;

  const handleDialogKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      onClose();
      return;
    }

    if (event.key !== "Tab") return;

    const focusableElements = dialogRef.current?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );

    if (!focusableElements?.length) {
      event.preventDefault();
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    if (event.shiftKey && document.activeElement === firstElement) {
      event.preventDefault();
      lastElement.focus();
    } else if (!event.shiftKey && document.activeElement === lastElement) {
      event.preventDefault();
      firstElement.focus();
    }
  };

  const handleAllowlist = () => {
    onAllowlist(threat.hostname);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 font-mono"
      onClick={onClose}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="threat-details-title"
        aria-describedby="threat-details-description"
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
        onKeyDown={handleDialogKeyDown}
        className="relative w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-lg bg-[#111111] border border-[#2D2D2D] p-6 shadow-2xl outline-none"
      >
        <button
          ref={closeButtonRef}
          type="button"
          onClick={onClose}
          aria-label="Close threat details"
          className="absolute top-4 right-4 text-neutral-400 hover:text-white focus-visible:outline-solid focus-visible:outline-2 focus-visible:outline-[#E5B83B] rounded cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2 mb-4 pr-8">
          <ShieldAlert className="w-5 h-5 text-[#E5B83B] shrink-0" />
          <h3
            id="threat-details-title"
            className="text-base font-bold text-neutral-100 uppercase tracking-wider"
          >
            Threat Analysis Record
          </h3>
        </div>

        <p id="threat-details-description" className="sr-only">
          Details of the detected threat, its risk evaluation, recorded action,
          and signals that contributed to the detection.
        </p>

        <div className="space-y-4 text-xs">
          <section aria-label="Target information">
            <div className="text-[10px] text-neutral-500 uppercase tracking-widest">
              Target Hostname
            </div>
            <div className="mt-0.5 break-all text-sm font-semibold text-neutral-200">
              {threat.hostname}
            </div>
            <div
              className="mt-0.5 break-all text-[11px] text-neutral-500"
              title={threat.url}
            >
              {threat.url}
            </div>
          </section>

          <div className="grid grid-cols-2 gap-3 rounded border border-[#262626] bg-[#171717] p-3">
            <section>
              <div className="text-[10px] text-neutral-500 uppercase">
                Risk Evaluation
              </div>
              <div className="mt-0.5 text-base font-black text-[#E5B83B]">
                {riskScore} / 100
              </div>
              <span
                className={`inline-flex mt-1 rounded border px-2 py-0.5 text-[10px] font-bold ${getRiskStyles(
                  threat.riskLevel
                )}`}
              >
                {threat.riskLevel}
              </span>
            </section>

            <section>
              <div className="text-[10px] text-neutral-500 uppercase">
                Action Taken
              </div>
              <div className="mt-0.5 wrap-break-word text-sm font-semibold text-neutral-200">
                {threat.action}
              </div>
              <span className="text-[10px] text-neutral-500">
                {formatTimestamp(threat.timestamp)}
              </span>
            </section>
          </div>

          <section>
            <div className="mb-1.5 text-[10px] text-neutral-500 uppercase tracking-widest">
              Detected Threat Vectors
            </div>

            {threat.signals.length === 0 ? (
              <div className="rounded border border-[#242424] bg-[#161616] p-3 text-neutral-500">
                No signal details were recorded for this threat.
              </div>
            ) : (
              <div className="max-h-40 space-y-1.5 overflow-y-auto pr-1">
                {threat.signals.map((signal, index) => {
                  const detail = threat.details?.[index];

                  return (
                    <div
                      key={`${signal}-${index}`}
                      className="rounded border border-[#242424] bg-[#161616] p-2"
                    >
                      <div className="text-[11px] font-bold text-[#E5B83B]">
                        {signal.replace(/_/g, " ")}
                      </div>

                      {detail && (
                        <div className="mt-0.5 wrap-break-word text-[10px] leading-relaxed text-neutral-400">
                          {detail}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          <div className="flex flex-wrap justify-end gap-2 border-t border-[#222222] pt-3">
            <button
              type="button"
              onClick={handleAllowlist}
              className="rounded border border-[#333333] bg-[#1C1C1C] px-3 py-1.5 font-medium text-neutral-200 transition-colors hover:bg-[#252525] focus-visible:outline-solid focus-visible:outline-2 focus-visible:outline-[#E5B83B] cursor-pointer"
            >
              Add Domain to Allowlist
            </button>

            <button
              type="button"
              onClick={onClose}
              className="rounded bg-[#E5B83B] px-4 py-1.5 font-bold text-black transition-colors hover:bg-[#F5CB5C] focus-visible:outline-solid focus-visible:outline-2 focus-visible:outline-white cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

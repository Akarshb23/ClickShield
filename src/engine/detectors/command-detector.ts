
import type { ThreatSignal } from "../../shared/types/signal";

// ==========================================================
// DETECTION PATTERNS
// ==========================================================

const ENCODED_POWERSHELL_PATTERN =
  /\bpowershell(?:\.exe)?\b[^\r\n]{0,160}-(?:e|enc|encodedcommand)\b\s+["']?[a-z0-9+/]{8,}={0,2}["']?/i;

const STEALTH_EXECUTION_PATTERN =
  /\bpowershell(?:\.exe)?\b[^\r\n]{0,160}(?:-w(?:indowstyle)?\s+(?:h|hidden)\b|-ep\s+bypass\b|-executionpolicy\s+bypass\b)/i;

const DOWNLOAD_EXECUTION_PATTERN =
  /\b(?:irm|iwr|invoke-webrequest|invoke-restmethod)\b[^\r\n]{0,300}(?:\|\s*(?:iex|invoke-expression)\b|;\s*(?:iex|invoke-expression)\b)|\b(?:iex|invoke-expression)\b[^\r\n]{0,200}\b(?:irm|iwr|invoke-webrequest|invoke-restmethod)\b/i;

const DOTNET_DOWNLOAD_EXECUTION_PATTERN =
  /\b(?:iex|invoke-expression)\b[^\r\n]{0,200}\.downloadstring\s*\(|\.downloadstring\s*\([^)]{0,300}\)[^\r\n]{0,160}\b(?:iex|invoke-expression)\b/i;

const LOLBINS_PATTERN =
  /\bmshta(?:\.exe)?\b[^\r\n]{0,200}(?:https?:\/\/|javascript:|vbscript:)|\bcertutil(?:\.exe)?\b[^\r\n]{0,200}(?:-urlcache\b[^\r\n]{0,160}https?:\/\/|-decode\b)|\bbitsadmin(?:\.exe)?\b[^\r\n]{0,200}\/transfer\b[^\r\n]{0,200}https?:\/\/|\bregsvr32(?:\.exe)?\b[^\r\n]{0,200}(?:\/i:|\/i\s+)[^\r\n]{0,160}(?:https?:\/\/|scrobj\.dll)|\brundll32(?:\.exe)?\b[^\r\n]{0,200}(?:javascript:|https?:\/\/)|\b(?:wscript|cscript)(?:\.exe)?\b[^\r\n]{0,200}https?:\/\//i;

const SHELL_EXECUTION_PATTERN =
  /\b(?:cmd(?:\.exe)?\s+\/[ck]|powershell(?:\.exe)?\s+-(?:c|command)\b)[ \t]+[^\r\n]{0,300}(?:https?:\/\/|downloadstring|invoke-expression|\biex\b|\bmshta\b|\bcertutil\b|\bbitsadmin\b|set-mppreference)/i;

const DECODER_EXECUTION_PATTERN =
  /(?:\[convert\]::frombase64string|\[system\.convert\]::frombase64string)\s*\([^)]{0,300}\)[^\r\n]{0,160}\b(?:iex|invoke-expression)\b|\b(?:iex|invoke-expression)\b[^\r\n]{0,160}\[convert\]::frombase64string/i;

const DEFENSE_EVASION_PATTERN =
  /\bset-mppreference\b[^\r\n]{0,160}-disablerealtimemonitoring\b[^\r\n]{0,80}\$true\b|\badd-mppreference\b[^\r\n]{0,160}-(?:exclusionpath|exclusionprocess|exclusionextension)\b|\bschtasks(?:\.exe)?\b[^\r\n]{0,160}\/create\b[^\r\n]{0,160}\/(?:sc\s+on(?:logon|start)|tr\s+)/i;

const REGISTRY_PERSISTENCE_PATTERN =
  /\breg(?:\.exe)?\s+add\s+["']?hklm\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\run\b/i;

const UNIX_REMOTE_PIPELINE_PATTERN =
  /\b(?:curl|wget)\b[^\r\n]{0,300}https?:\/\/[^\r\n]{0,160}\|\s*(?:bash|sh|zsh)\b/i;

const UNIX_BASE64_PIPELINE_PATTERN =
  /\bbase64\b[^\r\n]{0,120}(?:-d|--decode)\b[^\r\n]{0,160}\|\s*(?:bash|sh|zsh)\b/i;

const APPLESCRIPT_EXECUTION_PATTERN =
  /\bosascript\b[^\r\n]{0,160}\s+-e\b[^\r\n]{0,240}(?:do\s+shell\s+script|tell\s+application\s+["']terminal["'])/i;

const UNIX_SHELL_EXECUTION_PATTERN =
  /\b(?:bash|sh|zsh)\b\s+-c\s+["'][^"'\r\n]{0,250}(?:https?:\/\/|curl|wget|base64\s+-d|osascript)/i;

// ==========================================================
// SIGNAL CREATION
// ==========================================================

function createSignal(
  reason: string,
  snippet: string
): ThreatSignal {
  return {
    type: "EXECUTION_INSTRUCTION",
    reason,
    snippet,
  };
}

// ==========================================================
// MAIN DETECTOR
// ==========================================================

export function detectExecutionCommands(
  text: string
): ThreatSignal[] {
  const signals: ThreatSignal[] = [];

  if (typeof text !== "string" || !text.trim()) {
    return signals;
  }

  const content = text.slice(0, 100000);

  if (ENCODED_POWERSHELL_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected base64-encoded PowerShell command execution string.",
        "PowerShell -EncodedCommand pattern."
      )
    );
  }

  if (STEALTH_EXECUTION_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected stealth execution or execution policy bypass flags in command string.",
        "Stealth / Bypass command pattern."
      )
    );
  }

  if (DOWNLOAD_EXECUTION_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected memory download & execute cradle syntax connecting remote script retrieval with execution.",
        "In-memory script download cradle detected."
      )
    );
  }

  if (DOTNET_DOWNLOAD_EXECUTION_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected .NET remote script download followed by PowerShell expression execution.",
        ".NET download-and-execute pattern."
      )
    );
  }

  if (LOLBINS_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected living-off-the-land utility invocation with suspicious remote or script execution parameters.",
        "LOLBin utility abuse pattern."
      )
    );
  }

  if (SHELL_EXECUTION_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected direct shell command execution containing suspicious download, execution or security modification operations.",
        "Direct shell execution string."
      )
    );
  }

  if (DECODER_EXECUTION_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected Base64 payload decoding followed by dynamic command execution.",
        "In-line payload decoder."
      )
    );
  }

  if (DEFENSE_EVASION_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected command attempting to disable antivirus protections or establish suspicious persistence.",
        "Defense evasion / persistence attempt."
      )
    );
  }

  if (REGISTRY_PERSISTENCE_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected registry modification targeting a Windows Run persistence location.",
        "Registry persistence pattern."
      )
    );
  }

  if (
    UNIX_REMOTE_PIPELINE_PATTERN.test(content) ||
    UNIX_BASE64_PIPELINE_PATTERN.test(content)
  ) {
    signals.push(
      createSignal(
        "Detected dangerous remote script or decoded payload being piped directly into a shell.",
        "Remote execution pipeline detected."
      )
    );
  }

  // Corrected identifier
  if (APPLESCRIPT_EXECUTION_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected AppleScript attempting to execute shell commands or control Terminal.",
        "AppleScript shell execution detected."
      )
    );
  }

  if (UNIX_SHELL_EXECUTION_PATTERN.test(content)) {
    signals.push(
      createSignal(
        "Detected shell invocation containing remote download or decoded payload execution instructions.",
        "Suspicious Unix shell execution."
      )
    );
  }

  return signals;
}

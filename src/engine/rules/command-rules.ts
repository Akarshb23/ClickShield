export const COMMAND_PATTERNS = [
  /\bpowershell(\.exe)?\b/i,
  /\bcmd(\.exe)?\b/i,
  /\bmshta(\.exe)?\b/i,
  /\bbitsadmin(\.exe)?\b/i,
  /\bcurl\s+-/i,
  /\bwget\s+/i,
  /\birm\s+/i,
  /\biex\s+/i,
  /-enc(odedcommand)?\s+[a-z0-9+/=]{10,}/i,
  /windowstyle\s+hidden/i,
];

export const INSTRUCTION_PATTERNS = [
  /press (win|windows)( key)? \+ r/i,
  /open run dialog/i,
  /paste and press enter/i,
  /copy the code below and paste/i,
  /run terminal as administrator/i,
];


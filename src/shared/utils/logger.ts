const PREFIX = "[ClickShield]";

export const logger = {
  info: (...args: unknown[]) => {
    console.info(PREFIX, ...args);
  },
  warn: (...args: unknown[]) => {
    // Note: Chrome extensions report console.warn as red badge errors in chrome://extensions.
    // Using console.info with warning emoji preserves visibility without triggering false Chrome errors.
    console.info(PREFIX, "⚠️", ...args);
  },
  error: (...args: unknown[]) => {
    console.error(PREFIX, ...args);
  },
  debug: (...args: unknown[]) => {
    if (typeof import.meta !== "undefined" && import.meta.env?.DEV) {
      console.debug(PREFIX, ...args);
    }
  }
};

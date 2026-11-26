
/**
 * Phrases commonly used in fake CAPTCHA pages,
 * deceptive verification prompts and ClickFix attacks.
 *
 * Keep these phrases reasonably specific. Generic phrases
 * such as "security check" can cause false positives.
 */
export const CAPTCHA_KEYWORDS: string[] = [
  // --------------------------------------------------------
  // Human verification prompts
  // --------------------------------------------------------

  "verify that you are human",
  "verify you are human",
  "verify you are a human",
  "confirm you are human",
  "confirm you are a human",
  "confirm you are a real person",
  "i am not a robot",
  "i'm not a robot",
  "prove you are not a robot",
  "prove you are human",
  "human verification",
  "robot verification",

  // --------------------------------------------------------
  // CAPTCHA and browser verification prompts
  // --------------------------------------------------------

  "complete the captcha",
  "complete the security verification",
  "complete human verification",
  "click to verify that you are not a robot",
  "click verify to continue",
  "verification required to continue",
  "checking your browser before accessing",
  "checking if the site connection is secure",
  "your browser is being checked",
  "browser verification required",
  "cloudflare turnstile",
  "ddos-guard",

  // --------------------------------------------------------
  // Fake update and security prompts
  // --------------------------------------------------------

  "windows update required to continue",
  "chrome update required to view",
  "security update required to continue",
  "browser update required to continue",
  "install the required browser update",

  // --------------------------------------------------------
  // ClickFix / keyboard instruction lures
  // --------------------------------------------------------

  "press win + r to verify",
  "press win+r to verify",
  "press windows key + r to verify",
  "press the windows key and r",
  "open the run dialog to verify",
  "paste the verification command",
  "copy and paste the command to verify",
  "run the command to complete verification",
  "paste the command and press enter",
];

/**
 * Recognized CAPTCHA provider iframe locations.
 *
 * Format:
 *   hostname
 *   hostname/path
 *
 * The CAPTCHA detector should validate:
 * - HTTPS protocol
 * - Exact hostname or genuine subdomain
 * - Path boundaries when a path is specified
 *
 * Do not treat an arbitrary iframe as legitimate merely
 * because its URL contains a provider's brand name.
 */
export const LEGITIMATE_CAPTCHA_IFRAMES: string[] = [
  // Google reCAPTCHA
  "google.com/recaptcha",
  "recaptcha.net",

  // Cloudflare Turnstile
  "challenges.cloudflare.com",

  // Other recognized CAPTCHA providers
  "hcaptcha.com",
  "arkoselabs.com",
  "funcaptcha.com",
  "geetest.com",
];

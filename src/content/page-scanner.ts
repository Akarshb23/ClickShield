import type { ThreatSignal } from "../shared/types/signal";

import { detectCaptchaAnomalies } from "../engine/detectors/captcha-detector";

import { detectSuspiciousInstructions } from "../engine/detectors/instruction-detector";

import { detectExecutionCommands } from "../engine/detectors/command-detector";

import { detectDomainAnomalies } from "../engine/detectors/domain-detector";

import { detectBrandImpersonation } from "../engine/detectors/impersonation-detector";

// ==========================================================
// CONSTANTS
// ==========================================================
const MAX_PAGE_TEXT = 50000;

const MAX_CODE_CONTENT = 20000;

const MAX_ATTRIBUTE_CONTENT = 15000;

const MAX_SHADOW_TEXT = 20000;

const MAX_ATTRIBUTE_LENGTH = 2000;

const MAX_PROMINENT_TEXT = 5000;

const MAX_IFRAME_SOURCES = 100;

const MAX_IFRAME_SOURCE_LENGTH = 4096;

const MAX_LINKS_TO_INSPECT = 150;

const MAX_LINK_TEXT_LENGTH = 500;

const EXCLUDED_CONTENT_TAGS = new Set([

  "INPUT",

  "TEXTAREA",

  "SELECT",

  "OPTION",

  "SCRIPT",

  "STYLE",

  "NOSCRIPT",

  "TEMPLATE",

]);

const DATA_ATTRIBUTE_SELECTOR = [

  "[data-clipboard-text]",

  "[data-copy]",

  "[data-payload]",

  "[data-command]",

].join(", ");

const DATA_ATTRIBUTES = [

  "data-clipboard-text",

  "data-copy",

  "data-payload",

  "data-command",

] as const;

const FAKE_CAPTCHA_SELECTOR = [

  "button",

  '[role="button"]',

  '[role="checkbox"]',

  'input[type="checkbox"]',

  "label",

  'div[class*="captcha"]',

  'div[class*="turnstile"]',

  '[id*="captcha"]',

  '[id*="cf-turnstile"]',

  '[id*="verify"]',

  '[class*="verify"]',

  'div[class*="checkbox"]',

  'span[class*="checkbox"]',

].join(", ");

// ==========================================================
// SHADOW DOM ROOT DISCOVERY
// ==========================================================
type QueryRoot = Document | ShadowRoot;

function collectQueryRoots(): QueryRoot[] {

  const roots: QueryRoot[] = [document];

  const visited = new WeakSet<ShadowRoot>();

  function discover(root: QueryRoot): void {

    try {

      const walker = document.createTreeWalker(

        root,

        NodeFilter.SHOW_ELEMENT

      );

      let node: Node | null;

      while ((node = walker.nextNode())) {

        if (!(node instanceof Element)) {

          continue;

        }

        if (isIgnoredElement(node)) {

          continue;

        }

        if (

          node instanceof HTMLElement &&

          node.shadowRoot

        ) {

          const shadowRoot = node.shadowRoot;

          if (visited.has(shadowRoot)) {

            continue;

          }

          visited.add(shadowRoot);

          roots.push(shadowRoot);

          discover(shadowRoot);

        }

      }

    } catch {

      // A page may modify or detach DOM nodes during traversal.
    }

  }

  discover(document);

  return roots;

}

// ==========================================================
// INTERNAL UI EXCLUSION
// ==========================================================

function isIgnoredElement(element: Element): boolean {

  try {

    let current: Element | null = element;

    while (current) {

      if (

        current.hasAttribute("data-clickshield-ignore") ||

        current.id.toLowerCase().startsWith("clickshield")

      ) {

        return true;

      }

      if (current.parentElement) {

        current = current.parentElement;

        continue;

      }

      const root = current.getRootNode();

      if (root instanceof ShadowRoot) {

        current = root.host;

        continue;

      }

      break;

    }

    return false;

  } catch {

    return false;

  }

}

// ==========================================================
// FORM AND USER-CONTENT PRIVACY
// ==========================================================

function isExcludedContentElement(

  element: Element

): boolean {

  try {

    // Exclude form controls and executable/non-visible content.
    if (EXCLUDED_CONTENT_TAGS.has(element.tagName)) {

      return true;

    }

    // isContentEditable reflects the effective editing state,
    // including inheritance and contenteditable="false" overrides.
    if (

      element instanceof HTMLElement &&

      element.isContentEditable

    ) {

      return true;

    }

    let current: Element | null = element;

    while (current) {

      if (EXCLUDED_CONTENT_TAGS.has(current.tagName)) {

        return true;

      }

      if (current.parentElement) {

        current = current.parentElement;

        continue;

      }

      const root = current.getRootNode();

      if (root instanceof ShadowRoot) {

        current = root.host;

        if (

          current instanceof HTMLElement &&

          current.isContentEditable

        ) {

          return true;

        }

        continue;

      }

      break;

    }

    return false;

  } catch {

    return true;

  }

}

// ==========================================================
// TEXT NORMALIZATION
// ==========================================================

function normalizeText(text: string): string {

  return text

    .normalize("NFKC")

    .toLowerCase()

    .replace(/[\u200B-\u200D\uFEFF]/g, "")

    .replace(/\s+/g, " ")

    .trim();

}

// ==========================================================
// VISIBILITY CHECK
// ==========================================================

function isElementVisible(element: Element): boolean {

  try {

    const elementStyle = window.getComputedStyle(element);

    if (

      elementStyle.visibility === "hidden" ||

      elementStyle.visibility === "collapse"

    ) {

      return false;

    }

    let current: Element | null = element;

    while (current) {

      if (

        current.hasAttribute("hidden") ||

        current.getAttribute("aria-hidden") === "true"

      ) {

        return false;

      }

      const style = window.getComputedStyle(current);

      if (

        style.display === "none" ||

        style.opacity === "0" ||

        style.contentVisibility === "hidden"

      ) {

        return false;

      }

      if (current.parentElement) {

        current = current.parentElement;

        continue;

      }

      const root = current.getRootNode();

      if (root instanceof ShadowRoot) {

        current = root.host;

        continue;

      }

      break;

    }

    return true;

  } catch {

    return false;

  }

}

// ==========================================================
// TEXT EXTRACTION
// ==========================================================

function extractVisibleText(

  root: Node,

  maxLength: number

): string {

  if (maxLength <= 0) {

    return "";

  }

  const chunks: string[] = [];

  let totalLength = 0;

  try {

    const walker = document.createTreeWalker(

      root,

      NodeFilter.SHOW_TEXT

    );

    let node: Node | null;

    while (

      (node = walker.nextNode()) &&

      totalLength < maxLength

    ) {

      const parent = node.parentElement;

      if (!parent) {

        continue;

      }

      if (

        isIgnoredElement(parent) ||

        isExcludedContentElement(parent) ||

        !isElementVisible(parent)

      ) {

        continue;

      }

      const value = node.textContent?.trim();

      if (!value) {

        continue;

      }

      const remaining = maxLength - totalLength;

      const chunk = value.slice(0, remaining);

      if (!chunk) {

        continue;

      }

      chunks.push(chunk);

      totalLength += chunk.length;

    }

  } catch {

    // Ignore DOM traversal errors.
  }

  return chunks.join(" ");

}

// ==========================================================
// DATA ATTRIBUTE EXTRACTION
// ==========================================================

function extractDataAttributeSnippets(

  roots: QueryRoot[]

): string[] {

  const snippets: string[] = [];

  let totalLength = 0;

  for (const root of roots) {

    if (totalLength >= MAX_ATTRIBUTE_CONTENT) {

      break;

    }

    try {

      const elements = root.querySelectorAll(

        DATA_ATTRIBUTE_SELECTOR

      );

      for (const element of Array.from(elements)) {

        if (

          isIgnoredElement(element) ||

          isExcludedContentElement(element) ||

          !isElementVisible(element)

        ) {

          continue;

        }

        for (const attribute of DATA_ATTRIBUTES) {

          if (totalLength >= MAX_ATTRIBUTE_CONTENT) {

            break;

          }

          const value = element.getAttribute(attribute);

          if (!value || value.trim().length <= 5) {

            continue;

          }

          const remaining =

            MAX_ATTRIBUTE_CONTENT - totalLength;

          const snippet = value

            .trim()

            .slice(

              0,

              Math.min(MAX_ATTRIBUTE_LENGTH, remaining)

            );

          if (!snippet) {

            continue;

          }

          snippets.push(snippet);

          totalLength += snippet.length;

        }

      }

    } catch {

      continue;

    }

  }

  return snippets;

}

// ==========================================================
// CODE BLOCK EXTRACTION
// ==========================================================

function extractCodeSnippets(

  roots: QueryRoot[]

): string {

  const snippets: string[] = [];

  const seen = new Set<string>();

  let totalLength = 0;

  for (const root of roots) {

    if (totalLength >= MAX_CODE_CONTENT) {

      break;

    }

    try {

      const elements = root.querySelectorAll(

        "code, pre, blockquote"

      );

      for (const element of Array.from(elements)) {

        if (

          isIgnoredElement(element) ||

          isExcludedContentElement(element) ||

          !isElementVisible(element)

        ) {

          continue;

        }

        // A pre element already includes its nested code.
        if (

          element.tagName === "CODE" &&

          element.parentElement?.closest("pre")

        ) {

          continue;

        }

        const remaining =

          MAX_CODE_CONTENT - totalLength;

        const content = extractVisibleText(

          element,

          remaining

        );

        if (content.length <= 5) {

          continue;

        }

        if (seen.has(content)) {

          continue;

        }

        seen.add(content);

        snippets.push(content);

        totalLength += content.length;

      }

    } catch {

      continue;

    }

  }

  return snippets.join(" ");

}

// ==========================================================
// CAPTCHA ELEMENT DETECTION
// ==========================================================

function detectFakeCheckbox(

  roots: QueryRoot[]

): boolean {

  const verificationRegex =

    /\b(?:verify\s+(?:that\s+)?(?:you\s+are\s+)?(?:human|not\s+a\s+robot)|i['’]?m\s+not\s+a\s+robot|i\s+am\s+not\s+a\s+robot|captcha|turnstile|recaptcha|hcaptcha|verify\s+checkbox)\b/i;

  const identifierRegex =

    /(?:^|[\s\\\_-])(?:captcha|turnstile|recaptcha|hcaptcha|fake-checkbox)(?:$|[\s\\\_-])/i;

  const ariaRegex =

    /captcha|turnstile|verify\s+human/i;

  for (const root of roots) {

    try {

      const elements = root.querySelectorAll(

        FAKE_CAPTCHA_SELECTOR

      );

      for (const element of Array.from(elements)) {

        if (

          isIgnoredElement(element) ||

          !isElementVisible(element)

        ) {

          continue;

        }

        // Only inspect rendered text and non-sensitive
        // identifying attributes. Never inspect input.value.
        const text = normalizeText(

          element.textContent?.slice(0, 1000) || ""

        );

        const id = normalizeText(

          element.getAttribute("id") || ""

        );

        const className = normalizeText(

          element.getAttribute("class") || ""

        );

        const aria = normalizeText(

          element.getAttribute("aria-label") || ""

        );

        if (

          verificationRegex.test(text) ||

          identifierRegex.test(id) ||

          identifierRegex.test(className) ||

          ariaRegex.test(aria)

        ) {

          return true;

        }

      }

    } catch {

      continue;

    }

  }

  return false;

}

// ==========================================================
// IFRAME DISCOVERY
// ==========================================================

function resolveIframeSource(

  source: string

): string | null {

  if (

    typeof source !== "string" ||

    !source.trim() ||

    source.length > MAX_IFRAME_SOURCE_LENGTH

  ) {

    return null;

  }

  try {

    const url = new URL(

      source.trim(),

      document.baseURI

    );

    if (

      url.protocol !== "http:" &&

      url.protocol !== "https:"

    ) {

      return null;

    }

    if (url.href.length > MAX_IFRAME_SOURCE_LENGTH) {

      return null;

    }

    return url.href;

  } catch {

    return null;

  }

}

function collectIframeSources(

  roots: QueryRoot[]

): string[] {

  const sources = new Set<string>();

  for (const root of roots) {

    if (sources.size >= MAX_IFRAME_SOURCES) {

      break;

    }

    try {

      const iframes = root.querySelectorAll("iframe");

      for (const iframe of Array.from(iframes)) {

        if (

          sources.size >= MAX_IFRAME_SOURCES

        ) {

          break;

        }

        if (isIgnoredElement(iframe)) {

          continue;

        }

        const source =

          iframe.getAttribute("src")?.trim() ||

          iframe.getAttribute("data-src")?.trim() ||

          iframe.src;

        if (!source) {

          continue;

        }

        const resolvedSource =

          resolveIframeSource(source);

        if (resolvedSource) {

          sources.add(resolvedSource);

        }

      }

    } catch {

      continue;

    }

  }

  return Array.from(sources);

}

// ==========================================================
// BRAND IMPERSONATION CONTEXT
// ==========================================================

function extractProminentText(

  roots: QueryRoot[],

  titleText: string

): string {

  const chunks: string[] = [];

  let totalLength = 0;

  const normalizedTitle = titleText

    .trim()

    .slice(0, MAX_PROMINENT_TEXT);

  if (normalizedTitle) {

    chunks.push(normalizedTitle);

    totalLength += normalizedTitle.length;

  }

  const seen = new Set<string>();

  for (const root of roots) {

    if (totalLength >= MAX_PROMINENT_TEXT) {

      break;

    }

    try {

      const headings = root.querySelectorAll(

        "h1, [role='heading'][aria-level='1']"

      );

      for (const heading of Array.from(headings)) {

        if (

          isIgnoredElement(heading) ||

          isExcludedContentElement(heading) ||

          !isElementVisible(heading)

        ) {

          continue;

        }

        const remaining =

          MAX_PROMINENT_TEXT - totalLength;

        const text = extractVisibleText(

          heading,

          remaining

        ).trim();

        if (!text || seen.has(text)) {

          continue;

        }

        seen.add(text);

        chunks.push(text);

        totalLength += text.length;

      }

    } catch {

      continue;

    }

  }

  return chunks.join(" ");

}

// ==========================================================
// OUTGOING LINK DESTINATION ANALYSIS
// ==========================================================

function extractLinkDestinationSignals(roots: QueryRoot[]): ThreatSignal[] {
  const signals: ThreatSignal[] = [];
  const inspectedUrls = new Set<string>();
  let inspectedCount = 0;

  for (const root of roots) {
    if (inspectedCount >= MAX_LINKS_TO_INSPECT) break;
    try {
      const links = root.querySelectorAll<HTMLAnchorElement>("a[href]");
      for (const link of Array.from(links)) {
        if (inspectedCount >= MAX_LINKS_TO_INSPECT) break;
        if (isIgnoredElement(link) || isExcludedContentElement(link) || !isElementVisible(link)) continue;
        const rawHref = link.getAttribute("href")?.trim();
        if (!rawHref || rawHref.length > MAX_IFRAME_SOURCE_LENGTH) continue;

        let destination: URL;
        try { destination = new URL(rawHref, document.baseURI); } catch { continue; }
        if (destination.protocol !== "http:" && destination.protocol !== "https:") continue;
        const destinationHostname = destination.hostname.toLowerCase();
        if (!destinationHostname) continue;

        const key = `${destination.origin}${destination.pathname}`;
        if (inspectedUrls.has(key)) continue;
        inspectedUrls.add(key);
        inspectedCount += 1;
        signals.push(...detectDomainAnomalies(destinationHostname));
      }
    } catch {
      // Ignore links that mutate during scanning.
    }
  }
  return signals;
}

// SIGNAL DEDUPLICATION
// ==========================================================

function deduplicateSignals(

  signals: ThreatSignal[]

): ThreatSignal[] {

  const seen = new Set<string>();

  const result: ThreatSignal[] = [];

  for (const signal of signals) {

    const key = [

      signal.type,

      signal.reason,

      signal.snippet || "",

    ].join("\u0000");

    if (seen.has(key)) {

      continue;

    }

    seen.add(key);

    result.push(signal);

  }

  return result;

}

// ==========================================================
// PAGE SCANNER
// ==========================================================
export function scanPage(): ThreatSignal[] {

  try {

    // ------------------------------------------------------
    // 1. Validate document availability
    // ------------------------------------------------------
    if (

      typeof document === "undefined" ||

      typeof window === "undefined" ||

      !document.body ||

      !document.documentElement

    ) {

      return [];

    }

    // ------------------------------------------------------
    // 2. Do not scan ClickShield's own interface
    // ------------------------------------------------------
    if (

      document.body.hasAttribute("data-clickshield-ignore") ||

      document.documentElement.hasAttribute(

        "data-clickshield-ignore"

      ) ||

      document.body.id.toLowerCase().startsWith("clickshield") ||

      document.documentElement.id

        .toLowerCase()

        .startsWith("clickshield")

    ) {

      return [];

    }

    // ------------------------------------------------------
    // 3. Gather page context
    // ------------------------------------------------------
    const titleText = (document.title || "")

      .slice(0, 2000);

    const hostname =

      window.location.hostname || "local-file";

    const roots = collectQueryRoots();

    // ------------------------------------------------------
    // 4. Extract visible page text
    // ------------------------------------------------------
    const rawText = extractVisibleText(

      document.body,

      MAX_PAGE_TEXT

    );

    // ------------------------------------------------------
    // 5. Extract code examples
    // ------------------------------------------------------
    const codeSnippets =

      extractCodeSnippets(roots);

    // ------------------------------------------------------
    // 6. Extract explicitly marked command payloads
    // ------------------------------------------------------
    const dataAttributeSnippets =

      extractDataAttributeSnippets(roots);

    // ------------------------------------------------------
    // 7. Extract shadow DOM text
    // ------------------------------------------------------
    let shadowText = "";

    for (const root of roots.slice(1)) {

      if (shadowText.length >= MAX_SHADOW_TEXT) {

        break;

      }

      const remaining =

        MAX_SHADOW_TEXT - shadowText.length;

      const extracted = extractVisibleText(

        root,

        remaining

      );

      if (extracted) {

        shadowText += ` ${extracted}`;

      }

    }

    // ------------------------------------------------------
    // 8. Build detector inputs
    // ------------------------------------------------------
    const combinedContent = [

      titleText,

      rawText,

      codeSnippets,

      dataAttributeSnippets.join(" "),

      shadowText,

    ]

      .join(" ")

      .slice(

        0,

        MAX_PAGE_TEXT +

          MAX_CODE_CONTENT +

          MAX_ATTRIBUTE_CONTENT +

          MAX_SHADOW_TEXT

      );

    // ------------------------------------------------------
    // 9. CAPTCHA infrastructure analysis
    // ------------------------------------------------------
    const iframeSources =

      collectIframeSources(roots);

    const hasFakeCheckbox =

      detectFakeCheckbox(roots);

    // ------------------------------------------------------
    // 10. Prominent branding context
    // ------------------------------------------------------
    const prominentText = extractProminentText(

      roots,

      titleText

    );

    // ------------------------------------------------------
    // 11. Run modular detectors
    // ------------------------------------------------------
    const allSignals: ThreatSignal[] = [];

    // CAPTCHA anomalies
    allSignals.push(

      ...detectCaptchaAnomalies({

        text: combinedContent,

        hasIframes: iframeSources.length > 0,

        iframeSources,

        hasFakeCheckbox,

      })

    );

    // Social engineering and manual execution instructions
    allSignals.push(

      ...detectSuspiciousInstructions(combinedContent)

    );

    // Dangerous command execution patterns
    allSignals.push(

      ...detectExecutionCommands(combinedContent)

    );

    // Domain anomalies
    allSignals.push(

      ...detectDomainAnomalies(hostname)

    );

    // Inspect outgoing link destinations independently of the current page host.
    allSignals.push(...extractLinkDestinationSignals(roots));

    // Prominent brand impersonation
    allSignals.push(

      ...detectBrandImpersonation(

        prominentText,

        hostname

      )

    );

    // ------------------------------------------------------
    // 12. Return unique signals
    // ------------------------------------------------------
    return deduplicateSignals(allSignals);

  } catch (error) {

    // Never let page scanning break normal website execution.
    console.debug(

      "[ClickShield] Page scanning failed:",

      error

    );

    return [];

  }

}

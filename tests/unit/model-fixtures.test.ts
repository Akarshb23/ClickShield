import { describe, expect, it } from "vitest";
import normal from "../fixtures/normal-website.html?raw";
import documentation from "../fixtures/developer-documentation.html?raw";
import captcha from "../fixtures/legitimate-captcha.html?raw";
import clickfix from "../fixtures/simulated-clickfix.html?raw";
import { scanPage } from "../../src/content/page-scanner";
import { calculateRisk } from "../../src/engine/risk-engine";

describe("fixture pages through the scanner and trained classifier", () => {
  it.each([
    ["normal website", normal, "LOW"],
    ["developer documentation", documentation, "LOW"],
    ["legitimate CAPTCHA", captcha, "LOW"],
    ["simulated ClickFix", clickfix, "CRITICAL"],
  ])("classifies %s", (_name, html, level) => {
    const page = new DOMParser().parseFromString(html, "text/html");
    page.querySelectorAll("script, style").forEach(node => node.remove());
    document.title = page.title;
    document.body.innerHTML = page.body.innerHTML;
    // jsdom has no layout engine to compute rendered text.
    document.body.innerText = document.body.textContent ?? "";
    expect(calculateRisk(scanPage()).level).toBe(level);
  });
});

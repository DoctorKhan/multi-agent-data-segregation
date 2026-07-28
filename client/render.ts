/**
 * Pure HTML builders for the browser demo.
 *
 * Every string in `scenarios.json` is derived from untrusted model output, and
 * all of it is written through `innerHTML`. Escaping is therefore the only
 * control standing between the fixture and script execution on the published
 * page, so it lives here — in DOM-free functions that can be tested directly —
 * rather than inline in the render loop. `main.ts` may assign these results to
 * `innerHTML`; it must never build markup from fixture data itself.
 */

import type { ScenarioPresentation, DemoStep } from "./types.js";

export function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function comparisonHtml(
  scenarios: ScenarioPresentation[],
  activeScenario: number,
): string {
  return scenarios
    .map((scenario, index) => {
      const cls = scenario.outcome_kind === "leaked" ? "leaked" : "safe";
      return `
        <button type="button" class="comp-card ${index === activeScenario ? "active" : ""}" data-index="${index}">
          <h3>${escapeHtml(scenario.comparison_label)}</h3>
          <div class="outcome ${cls}">${escapeHtml(scenario.outcome)}</div>
        </button>`;
    })
    .join("");
}

export function tabsHtml(
  scenarios: ScenarioPresentation[],
  activeScenario: number,
): string {
  return scenarios
    .map(
      (scenario, index) =>
        `<button type="button" class="tab ${index === activeScenario ? "active" : ""}" data-index="${index}">
          Scenario ${escapeHtml(scenario.label)}
        </button>`,
    )
    .join("");
}

export function headerHtml(scenario: ScenarioPresentation): string {
  return `
    <h2>Scenario ${scenario.number} · ${escapeHtml(scenario.title)}</h2>
    <p>${escapeHtml(scenario.subtitle)}</p>
    <p class="policy">Policy: ${escapeHtml(scenario.policy)}</p>`;
}

export function trackHtml(steps: DemoStep[], activeStep: number): string {
  return steps
    .map(
      (_, index) =>
        `<button type="button" class="step-dot ${index < activeStep ? "done" : ""} ${index === activeStep ? "current" : ""}" data-index="${index}" aria-label="Step ${index + 1}"></button>`,
    )
    .join("");
}

export function stepCardHtml(step: DemoStep): string {
  return `
    <h3>${escapeHtml(step.title)}</h3>
    ${step.actor ? `<div class="actor">${escapeHtml(step.actor)}</div>` : ""}
    <div class="body">${escapeHtml(step.body)}</div>
    ${step.code ? `<pre><code>${escapeHtml(step.code)}</code></pre>` : ""}`;
}

export function highlightClass(step: DemoStep): string {
  if (step.highlight === "danger") return "danger";
  if (step.highlight === "safe") return "safe";
  return "";
}

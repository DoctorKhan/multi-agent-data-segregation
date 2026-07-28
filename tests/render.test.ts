/**
 * The published page writes fixture data into `innerHTML`, and every string in
 * that fixture originates in untrusted model output. Escaping is the only
 * control preventing script execution on the public site, so it is tested
 * directly here rather than assumed.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import payload from "../client/scenarios.json";
import {
  comparisonHtml,
  escapeHtml,
  headerHtml,
  stepCardHtml,
  tabsHtml,
} from "../client/render.js";
import type { DemoPayload, DemoStep, ScenarioPresentation } from "../client/types.js";

const HOSTILE = `<script>alert(1)</script>" onmouseover="alert(2)' & <img src=x onerror=alert(3)>`;

function hostileStep(): DemoStep {
  return {
    id: "boundary",
    title: HOSTILE,
    body: HOSTILE,
    actor: HOSTILE,
    code: HOSTILE,
    highlight: "danger",
  };
}

function hostileScenario(): ScenarioPresentation {
  return {
    number: 1,
    title: HOSTILE,
    label: HOSTILE,
    comparison_label: HOSTILE,
    subtitle: HOSTILE,
    policy: HOSTILE,
    outcome: HOSTILE,
    outcome_kind: "leaked",
    steps: [hostileStep()],
  };
}

/** Strip the markup the builder itself emits, leaving only interpolated data. */
function interpolatedOnly(html: string): string {
  return html.replace(/<\/?(?:button|h2|h3|p|div|pre|code)[^>]*>/g, "");
}

describe("escapeHtml", () => {
  it("neutralizes every character that can break out of markup", () => {
    expect(escapeHtml("<")).toBe("&lt;");
    expect(escapeHtml(">")).toBe("&gt;");
    expect(escapeHtml('"')).toBe("&quot;");
    expect(escapeHtml("'")).toBe("&#39;");
    expect(escapeHtml("&")).toBe("&amp;");
  });

  it("escapes the ampersand first so entities are not double-decoded", () => {
    // Escaping `<` before `&` would yield `&amp;lt;`, rendering a literal "<".
    expect(escapeHtml("<")).toBe("&lt;");
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
  });

  it("removes the script tag from a hostile payload", () => {
    const escaped = escapeHtml(HOSTILE);
    expect(escaped).not.toContain("<script");
    expect(escaped).not.toContain("<img");
    expect(escaped).not.toContain('"');
  });

  it("leaves ordinary transcript text readable", () => {
    expect(escapeHtml("[tool] read owner=client_a key=secret")).toBe(
      "[tool] read owner=client_a key=secret",
    );
  });
});

describe("HTML builders reject hostile fixture data", () => {
  const builders: [string, () => string][] = [
    ["comparisonHtml", () => comparisonHtml([hostileScenario()], 0)],
    ["tabsHtml", () => tabsHtml([hostileScenario()], 0)],
    ["headerHtml", () => headerHtml(hostileScenario())],
    ["stepCardHtml", () => stepCardHtml(hostileStep())],
  ];

  for (const [name, build] of builders) {
    it(`${name} emits no tag or attribute from fixture data`, () => {
      const data = interpolatedOnly(build());
      expect(data).not.toContain("<script");
      expect(data).not.toContain("<img");
      // `onerror=` may survive as inert text; what must not survive is any
      // character that could close a tag or an attribute around it.
      expect(data).not.toMatch(/[<>"']/);
    });
  }
});

describe("the committed fixture stays renderable", () => {
  const scenarios = (payload as DemoPayload).scenarios;

  it("escapes every field the renderer interpolates", () => {
    for (const scenario of scenarios) {
      expect(interpolatedOnly(headerHtml(scenario))).not.toMatch(/[<>]/);
      for (const step of scenario.steps) {
        expect(interpolatedOnly(stepCardHtml(step))).not.toMatch(/[<>]/);
      }
    }
  });
});

describe("main.ts delegates all markup construction", () => {
  it("never interpolates fixture data into innerHTML directly", () => {
    // A new inline template in main.ts would bypass the escaping tested above.
    const source = readFileSync(new URL("../client/main.ts", import.meta.url), "utf8");
    const assignments = source.match(/innerHTML\s*=\s*(.*)/g) ?? [];
    expect(assignments.length).toBeGreaterThan(0);
    for (const assignment of assignments) {
      expect(assignment).not.toContain("`");
    }
    expect(source).not.toContain("escapeHtml(");
  });
});

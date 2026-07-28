/**
 * The browser demo renders `client/scenarios.json`, which the Python lab
 * generates. It holds no policy logic of its own, so these tests verify the
 * contract between the two surfaces rather than re-testing the executors:
 * the fixture is renderable, and the security claims it puts in front of a
 * visitor match what the Python executors actually decided.
 *
 * Enforcement behavior is covered by the Python suite. If a decision here looks
 * wrong, fix it in `src/data_segregation_lab/` and run `just export-demo`.
 */

import { describe, expect, it } from "vitest";
import payload from "../client/scenarios.json";
import type { DemoPayload, ScenarioPresentation } from "../client/types.js";

const scenarios = (payload as DemoPayload).scenarios;

function byNumber(n: number): ScenarioPresentation {
  const scenario = scenarios.find((s) => s.number === n);
  if (!scenario) throw new Error(`scenario ${n} missing from fixture`);
  return scenario;
}

function boundaryOf(n: number) {
  const step = byNumber(n).steps.find((s) => s.id === "boundary");
  if (!step) throw new Error(`scenario ${n} has no enforcement step`);
  return step;
}

describe("fixture contract", () => {
  it("ships every scenario the Python lab defines", () => {
    expect(scenarios.map((s) => s.number)).toEqual([1, 2, 3, 4]);
  });

  it("gives every step the fields the renderer reads", () => {
    for (const scenario of scenarios) {
      expect(scenario.steps.length).toBeGreaterThan(0);
      for (const step of scenario.steps) {
        expect(step.id).toBeTruthy();
        expect(step.title).toBeTruthy();
        expect(typeof step.body).toBe("string");
        expect(["danger", "safe", "neutral"]).toContain(step.highlight);
      }
    }
  });

  it("labels every scenario for the tabs and comparison cards", () => {
    for (const scenario of scenarios) {
      expect(scenario.label).toBeTruthy();
      expect(scenario.comparison_label).toBeTruthy();
      expect(scenario.policy).toBeTruthy();
    }
  });

  it("walks every scenario to an enforcement decision", () => {
    // Only audit evidence may follow the boundary; nothing re-decides after it.
    for (const scenario of scenarios) {
      const ids = scenario.steps.map((s) => s.id);
      const boundary = ids.indexOf("boundary");
      expect(boundary).toBeGreaterThanOrEqual(0);
      expect(ids.slice(boundary + 1)).toEqual(
        ids.slice(boundary + 1).filter((id) => id === "lineage"),
      );
    }
  });

  it("shows the provenance chain after the OGI block", () => {
    const lineage = byNumber(4).steps.find((s) => s.id === "lineage");
    expect(lineage?.code).toContain("ANOMALY");
  });
});

describe("security claims shown to visitors", () => {
  it("marks only the vulnerable scenario as leaked", () => {
    const leaked = scenarios.filter((s) => s.outcome_kind === "leaked");
    expect(leaked.map((s) => s.number)).toEqual([1]);
  });

  it("shows the vulnerable path returning Client A's data", () => {
    expect(byNumber(1).outcome).toBe("ALLOWED / LEAKED");
    const boundary = boundaryOf(1);
    expect(boundary.body).toContain("ALLOW");
    expect(boundary.body).toContain("42");
    expect(boundary.highlight).toBe("danger");
  });

  it("shows the protected path blocking the same request", () => {
    expect(boundaryOf(2).body).toContain("BLOCK");
    expect(boundaryOf(2).highlight).toBe("safe");
    expect(byNumber(2).outcome).toBe("BLOCKED / SAFE");
  });

  it("keeps peer injection blocked under a hardened orchestrator", () => {
    const scenario = byNumber(3);
    expect(scenario.policy).toContain("orchestrator prompt=hardened");
    expect(boundaryOf(3).body).toContain("BLOCK");
    expect(scenario.outcome).toBe("BLOCKED / SAFE");
  });

  it("still displays the injected tool call as evidence", () => {
    // A scenario that never surfaced the injection would prove nothing.
    const peerStep = byNumber(3).steps.find((s) => s.id === "peer-model")!;
    expect(peerStep.code).toContain("[tool]");
  });

  it("forwards exactly one proposal under hardening", () => {
    const orchestrator = byNumber(3).steps.find((s) => s.id === "orchestrator")!;
    const forwarded = orchestrator.body
      .split("\n")
      .filter((line) => line.includes("EXEC:"));
    expect(forwarded).toHaveLength(1);
  });

  it("covers the OGI scenario the CLI demonstrates", () => {
    expect(byNumber(4).title).toBe("OGI PROVENANCE");
    expect(boundaryOf(4).body).toContain("BLOCK");
    expect(boundaryOf(4).highlight).toBe("safe");
  });
});

import { describe, expect, it } from "vitest";
import { leaked } from "../shared/models.js";
import {
  runHardenedInjectionScenario,
  runProtectedScenario,
  runVulnerableScenario,
} from "../shared/scenario.js";

describe("browser demo scenarios", () => {
  it("vulnerable path leaks cross-owner read", () => {
    const result = runVulnerableScenario();
    expect(leaked(result)).toBe(true);
    expect(result.readExecution.decision).toBe("allow");
    expect(result.readExecution.value).toBe("42");
  });

  it("protected path blocks the same request", () => {
    const result = runProtectedScenario();
    expect(leaked(result)).toBe(false);
    expect(result.readExecution.decision).toBe("block");
    expect(result.readExecution.value ?? null).toBeNull();
  });

  it("hardened peer injection stays blocked", () => {
    const result = runHardenedInjectionScenario();
    expect(result.attack).toBe("peer_injection");
    expect(result.orchestratorHardening).toBe("hardened");
    expect(leaked(result)).toBe(false);
    expect(result.readExecution.decision).toBe("block");
  });
});

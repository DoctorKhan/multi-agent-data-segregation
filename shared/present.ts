import type { ScenarioResult, ScenarioPresentation } from "./models.js";
import { leaked } from "./models.js";
import { formatToolCall } from "./toolProtocol.js";

function transcript(actor: string, text: string): string {
  const safe = text.trim() || "<empty>";
  return safe
    .split("\n")
    .map((line) => `${actor}: ${line}`)
    .join("\n");
}

function buildSteps(result: ScenarioResult): ScenarioPresentation["steps"] {
  const writeCall = result.writeExecution.call;
  const readCall = result.readExecution.call;
  const steps = [
    {
      id: "store-request",
      title: "Client A stores private data",
      actor: "client_a → orchestrator",
      body: result.clientAMessage.content,
    },
    {
      id: "store-model",
      title: "Client A model output",
      actor: "client_a",
      body: transcript("client_a", result.clientAOutput),
      code: writeCall ? formatToolCall(writeCall) : undefined,
    },
    {
      id: "stored",
      title: "Memory state",
      actor: "store",
      body: `client_a / secret = ${JSON.stringify(result.storedValue)}`,
      highlight: "neutral" as const,
    },
    {
      id: "read-request",
      title: "Client B requests Client A's secret",
      actor: "client_b → orchestrator",
      body: result.clientBMessage.content,
    },
    {
      id: "peer-model",
      title: "Client B model output (untrusted)",
      actor: "client_b",
      body: transcript("client_b", result.clientBOutput),
      code: result.clientBOutput.includes("[tool]")
        ? result.clientBOutput
            .split("\n")
            .find((l) => l.includes("[tool]"))
        : undefined,
    },
    {
      id: "orchestrator",
      title: "Orchestrator forwards tool proposal",
      actor: "orchestrator",
      body: transcript("orchestrator", result.orchestratorOutput),
      code: readCall ? formatToolCall(readCall) : undefined,
    },
    {
      id: "boundary",
      title: "Enforcement boundary",
      actor: "executor",
      body:
        result.readExecution.decision === "block"
          ? `BLOCK — requester (${result.requester}) ≠ target owner (${readCall?.owner ?? "?"})`
          : result.readExecution.value != null
            ? `ALLOW — returned ${JSON.stringify(result.readExecution.value)} to ${result.requester}`
            : `Decision: ${result.readExecution.decision}`,
      code: readCall ? formatToolCall(readCall) : undefined,
      highlight:
        result.readExecution.decision === "block"
          ? ("safe" as const)
          : leaked(result)
            ? ("danger" as const)
            : ("neutral" as const),
    },
  ];
  return steps;
}

export function presentScenario(number: number, result: ScenarioResult): ScenarioPresentation {
  const protected_ = result.mode === "protected";
  const title = protected_ ? "PROTECTED" : "INTENTIONALLY VULNERABLE";

  let subtitle: string;
  if (result.attack === "peer_injection") {
    subtitle = protected_
      ? "Peer injection + hardened orchestrator prompt + requester-scoped executor."
      : "Peer injection succeeds only because authorization is missing.";
  } else {
    subtitle = protected_
      ? "Requester-scoped authorization runs before storage access."
      : "The executor trusts the owner supplied by untrusted model text.";
  }

  let policy = protected_ ? "requester must equal target owner" : "none (unsafe)";
  if (result.attack === "peer_injection") {
    policy += `; orchestrator prompt=${result.orchestratorHardening}`;
  }

  let outcome: string;
  let outcomeKind: ScenarioPresentation["outcomeKind"];
  if (leaked(result)) {
    outcome = "ALLOWED / LEAKED";
    outcomeKind = "leaked";
  } else if (result.readExecution.decision === "block") {
    outcome = "BLOCKED / SAFE";
    outcomeKind = "safe";
  } else {
    outcome = "NO LEAK";
    outcomeKind = "neutral";
  }

  return {
    number,
    title,
    subtitle,
    policy,
    outcome,
    outcomeKind,
    steps: buildSteps(result),
  };
}

export function presentDemo(
  vulnerable: ScenarioResult,
  protectedResult: ScenarioResult,
  hardenedInjection: ScenarioResult,
): ScenarioPresentation[] {
  return [
    presentScenario(1, vulnerable),
    presentScenario(2, protectedResult),
    presentScenario(3, hardenedInjection),
  ];
}

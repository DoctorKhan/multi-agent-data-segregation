import type { ScenarioMode, ToolCall, ToolExecution } from "./models.js";
import type { InMemoryStore } from "./storage.js";

export interface ToolExecutor {
  readonly mode: ScenarioMode;
  execute(requester: string, call: ToolCall): ToolExecution;
}

export class VulnerableToolExecutor implements ToolExecutor {
  readonly mode = "vulnerable" as const;

  constructor(private readonly store: InMemoryStore) {}

  execute(_requester: string, call: ToolCall): ToolExecution {
    if (call.action === "write") {
      this.store.write(call.owner, call.key, call.value ?? "");
      return { decision: "allow", call };
    }
    return {
      decision: "allow",
      call,
      value: this.store.read(call.owner, call.key),
    };
  }
}

export class OwnerScopedToolExecutor implements ToolExecutor {
  readonly mode = "protected" as const;

  constructor(private readonly store: InMemoryStore) {}

  execute(requester: string, call: ToolCall): ToolExecution {
    if (requester !== call.owner) {
      return { decision: "block", call };
    }
    if (call.action === "write") {
      this.store.write(call.owner, call.key, call.value ?? "");
      return { decision: "allow", call };
    }
    return {
      decision: "allow",
      call,
      value: this.store.read(call.owner, call.key),
    };
  }
}

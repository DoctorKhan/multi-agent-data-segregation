export type ToolAction = "read" | "write";
export type Decision = "allow" | "block" | "no_decision";
export type ScenarioMode = "vulnerable" | "protected";
export type AttackKind = "cross_owner" | "peer_injection";
export type Hardening = "hardened" | "moderate" | "naive";

export interface ToolCall {
  action: ToolAction;
  owner: string;
  key: string;
  value?: string | null;
}

export interface AgentMessage {
  sender: string;
  recipient: string;
  content: string;
}

export class Participant {
  inbox: AgentMessage[] = [];

  constructor(public readonly name: string) {}

  send(recipient: string, content: string): AgentMessage {
    return { sender: this.name, recipient, content: content.trim() };
  }

  receive(message: AgentMessage): void {
    this.inbox.push(message);
  }

  flushInbox(): AgentMessage[] {
    const messages = [...this.inbox];
    this.inbox.length = 0;
    return messages;
  }
}

export interface ToolExecution {
  decision: Decision;
  call?: ToolCall | null;
  value?: string | null;
  reason?: string | null;
}

export interface ScenarioResult {
  mode: ScenarioMode;
  attack: AttackKind;
  orchestratorHardening: Hardening;
  requester: string;
  clientAMessage: AgentMessage;
  clientAOutput: string;
  writeExecution: ToolExecution;
  storedValue: string | null;
  clientBMessage: AgentMessage;
  clientBOutput: string;
  orchestratorOutput: string;
  readExecution: ToolExecution;
}

export function leaked(result: ScenarioResult): boolean {
  const call = result.readExecution.call;
  return (
    result.readExecution.decision === "allow" &&
    result.readExecution.value != null &&
    call != null &&
    result.requester !== call.owner
  );
}

export interface DemoStep {
  id: string;
  title: string;
  actor?: string;
  body: string;
  code?: string;
  highlight?: "danger" | "safe" | "neutral";
}

export interface ScenarioPresentation {
  number: number;
  title: string;
  subtitle: string;
  policy: string;
  outcome: string;
  outcomeKind: "leaked" | "safe" | "neutral";
  steps: DemoStep[];
}

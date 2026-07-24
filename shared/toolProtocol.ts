import type { ToolCall } from "./models.js";
import { PARTICIPANTS } from "./protocol.js";

const KEY_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const MAX_VALUE_CHARS = 256;

class ToolCallParseError extends Error {}

function parseArguments(parts: string[]): Record<string, string> {
  const arguments_: Record<string, string> = {};
  for (const part of parts) {
    if (!part.includes("=")) {
      throw new ToolCallParseError(`Missing '=' in tool argument: ${part}`);
    }
    const eq = part.indexOf("=");
    const name = part.slice(0, eq);
    let value = part.slice(eq + 1);
    if (!name || !value) {
      throw new ToolCallParseError("Tool argument names and values cannot be empty");
    }
    if (name in arguments_) {
      throw new ToolCallParseError(`Duplicate tool argument: ${name}`);
    }
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    arguments_[name] = value;
  }
  return arguments_;
}

function parseToolLine(line: string): ToolCall {
  const parts = line.split(/\s+/);
  if (parts.length < 4) throw new ToolCallParseError("Tool call is incomplete");

  const rawAction = parts[1];
  if (rawAction !== "read" && rawAction !== "write") {
    throw new ToolCallParseError(`Unsupported tool action: ${rawAction}`);
  }

  const arguments_ = parseArguments(parts.slice(2));
  const expected =
    rawAction === "write"
      ? new Set(["owner", "key", "value"])
      : new Set(["owner", "key"]);

  const keys = new Set(Object.keys(arguments_));
  if (keys.size !== expected.size || ![...expected].every((k) => keys.has(k))) {
    throw new ToolCallParseError(
      `${rawAction} requires exactly these arguments: ${[...expected].sort().join(", ")}`,
    );
  }

  return {
    action: rawAction,
    owner: arguments_.owner,
    key: arguments_.key,
    value: rawAction === "write" ? arguments_.value : null,
  };
}

export function detectToolCalls(text: string): ToolCall[] {
  const calls: ToolCall[] = [];
  for (const rawLine of text.split("\n")) {
    let line = rawLine.trim();
    if (line.startsWith("EXEC:")) line = line.slice(5).trim();
    if (!line.startsWith("[tool]")) continue;
    try {
      calls.push(parseToolLine(line));
    } catch {
      continue;
    }
  }
  return calls;
}

export function sanitizeToolCall(call: ToolCall): ToolCall | null {
  const owner = call.owner.trim();
  if (!PARTICIPANTS.has(owner)) return null;

  const key = call.key.trim();
  if (!KEY_PATTERN.test(key)) return null;

  if (call.action === "write") {
    let value = (call.value ?? "").trim();
    if (value.length > MAX_VALUE_CHARS) value = value.slice(0, MAX_VALUE_CHARS);
    return { action: call.action, owner, key, value };
  }

  return { action: call.action, owner, key, value: null };
}

export function formatToolCall(call: ToolCall): string {
  let fields = `owner="${call.owner}", key="${call.key}"`;
  if (call.value != null) fields += `, value="${call.value}"`;
  return `${call.action}(${fields})`;
}

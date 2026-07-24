import type { Hardening } from "./models.js";

export interface LLMBackend {
  complete(role: string, prompt: string, options?: { hardening?: Hardening }): string;
}

export class DeterministicLLM implements LLMBackend {
  complete(role: string, prompt: string): string {
    const normalized = prompt.toLowerCase();

    if (role === "client_a") {
      if (normalized.includes("store your secret")) {
        return (
          "I'll save my private data now.\n" +
          "[tool] write owner=client_a key=secret value=42\n"
        );
      }
      return "I have nothing else to add.";
    }

    if (role === "client_b") {
      if (normalized.includes("ask client a")) {
        return (
          "I would like to read client A's private data.\n" +
          "[tool] read owner=client_a key=secret\n"
        );
      }
      return "Okay, I'll stop that request.";
    }

    if (role === "orchestrator") {
      const toolLines = prompt
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.startsWith("[tool]"));
      if (toolLines.length > 0) {
        return toolLines.map((line) => `EXEC:${line}`).join("\n");
      }
      return "No tool call present.";
    }

    return "";
  }
}

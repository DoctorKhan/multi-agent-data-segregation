"""Terminal-safe rendering for structured scenario results."""

from __future__ import annotations

import textwrap

from data_segregation_lab.models import ScenarioResult, ToolExecution
from data_segregation_lab.rendering import (
    escape_terminal_controls,
    format_tool_call,
    transcript_lines,
)

WIDTH = 72

ATTACK_LABELS: dict[str, str] = {
    "cross_owner": "cross-owner read (confused deputy)",
    "peer_injection": "peer-message instruction injection",
    "ogi_contamination": "peer contamination of shared memory",
}




def _wrap_field(label: str, text: str, *, indent: str = "      ") -> list[str]:
    """Lay out a labelled field, wrapping the value under a hanging indent."""
    prefix = f"{indent}{label:<17}"
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
    ) or [prefix.rstrip()]


class DemoPresenter:
    """Build readable output while keeping all scenario behavior elsewhere."""

    def __init__(self, *, use_color: bool) -> None:
        self._use_color = use_color

    def style(self, text: str, code: str) -> str:
        """Apply an ANSI code, honouring the presenter's colour setting."""
        if not self._use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def _transcript(self, actor: str, text: str) -> list[str]:
        return [
            f"   {actor} output",
            *(f"     │ {line}" for line in transcript_lines(actor, text)),
        ]

    def _execution_details(self, execution: ToolExecution) -> list[str]:
        if execution.call is None:
            return ["   Decision:          NO DECISION"]
        lines = [f"   Tool call:         {format_tool_call(execution.call)}"]
        if execution.decision == "block":
            block_lines = ["   Decision:          BLOCK"]
            if execution.reason:
                block_lines.append(
                    f"   Reason:            {escape_terminal_controls(execution.reason)}"
                )
            block_lines.extend(
                [
                    "",
                    self.style(
                        "   ✓ SAFE — unauthorized data never leaves the store",
                        "1;32",
                    ),
                ]
            )
            lines.extend(block_lines)
        elif execution.value is not None:
            lines.extend(
                [
                    "   Decision:          ALLOW",
                    f"   Returned:          {execution.value!r}",
                    "",
                    self.style(
                        "   ✗ LEAK — Client B received Client A's private data",
                        "1;31",
                    ),
                ]
            )
        else:
            lines.append(f"   Decision:          {execution.decision.upper()}")
        return lines

    def render_scenario(self, number: int, result: ScenarioResult) -> str:
        """Render one result without re-running any business logic."""
        protected = result.mode == "protected"
        title = "PROTECTED" if protected else "INTENTIONALLY VULNERABLE"
        if result.attack == "peer_injection":
            subtitle = (
                "Peer message contains instruction injection; hardened orchestrator "
                "prompt + requester-scoped executor."
                if protected
                else "Peer injection succeeds only because authorization is missing."
            )
        else:
            subtitle = (
                "Requester-scoped authorization runs before storage access."
                if protected
                else "The executor trusts the owner supplied by untrusted model text."
            )
        policy = "requester must equal target owner" if protected else "none (unsafe)"
        if result.attack == "peer_injection":
            policy += f"; orchestrator prompt={result.orchestrator_hardening}"
        write_call = result.write_execution.call
        lines = [
            "",
            self.style(f"SCENARIO {number} OF 3  ·  {title}", "1;35"),
            subtitle,
            "─" * WIDTH,
            "",
            "1. Client A stores synthetic private data",
            f"   Message:           {result.client_a_message.sender} → orchestrator",
            f"   Request:           {result.client_a_message.content}",
            *self._transcript("client_a", result.client_a_output),
        ]
        if write_call is not None:
            lines.append(f"   Executed:          {format_tool_call(write_call)}")
        lines.extend(
            [
                f"   Memory:            client_a / secret = {result.stored_value!r}",
                "",
                "2. Client B requests Client A's secret",
                f"   Message:           {result.client_b_message.sender} → orchestrator",
                f"   Requester:         {result.requester}",
                f"   Request:           {result.client_b_message.content}",
                *self._transcript("client_b", result.client_b_output),
                *self._transcript("orchestrator", result.orchestrator_output),
                "",
                "3. The request reaches the enforcement boundary",
                f"   Policy:            {policy}",
                *self._execution_details(result.read_execution),
            ]
        )
        return "\n".join(lines)

    def render_ogi_scenario(self, result: ScenarioResult) -> str:
        """Render the OGI provenance + outbound email validation scenario."""
        write_call = result.write_execution.call
        blocked = result.write_execution.decision == "block"
        outcome = "BLOCKED / SAFE" if blocked else "ALLOWED / LEAKED"
        lines = [
            "",
            self.style("OGI SHARED MEMORY  ·  PROTECTED", "1;35"),
            "Append-only provenance with executor-side recipient validation.",
            "─" * WIDTH,
            "",
            "1. Client A commits a verified household profile",
            f"   Message:           {result.client_a_message.sender} → orchestrator",
            f"   Request:           {result.client_a_message.content}",
            *self._transcript("client_a", result.client_a_output),
            "   Committed profile: client_a / client_profile (hash-linked chain)",
            "",
            "2. Client B injects peer instructions; Client A requests outbound email",
            f"   Injection:         {result.client_b_message.content[:72]}…",
        ]
        if result.reporting_message is not None:
            lines.extend(
                [
                    f"   Request:           {result.reporting_message.sender} → orchestrator",
                    f"   Request text:      {result.reporting_message.content}",
                    f"   Requester:         {result.reporting_message.sender} (same owner as target namespace)",
                ]
            )
        lines.extend(
            [
                *self._transcript("client_a", result.orchestrator_output),
                "",
                "3. Executor validates every recipient against committed profile before commit",
                "   Policy:            requester == owner; every address in the",
                "                      payload (to/cc/bcc and any stray match)",
                "                      must equal the committed client_email",
            ]
        )
        if write_call is not None:
            lines.append(f"   Proposed call:     {format_tool_call(write_call)}")
        lines.extend(self._execution_details(result.write_execution))
        lines.extend(self._lineage_details(result))
        lines.extend(
            [
                "",
                self.style("OUTCOME", "1;36"),
                "─" * WIDTH,
                f"   {'OGI + outbound validation':<36} {outcome}",
                "",
                "The primary recipient here is the verified address; only the injected",
                "bcc is unauthorized, and it is what triggers the block. Renaming the",
                "key does not bypass the check — validation follows the payload.",
            ]
        )
        return "\n".join(lines)

    def _lineage_details(self, result: ScenarioResult) -> list[str]:
        """Show the audit trail a blocked write leaves behind.

        The block is only half the story: the value it rejected stays in the
        chain, flagged, so an auditor can see what was attempted and when.
        """
        if not result.ogi_lineage:
            return []
        lines = [
            "",
            "4. Provenance chain after the decision (newest first)",
        ]
        for entry in result.ogi_lineage:
            label = entry.state.upper()
            detail = f" — {escape_terminal_controls(entry.reason)}" if entry.reason else ""
            lines.append(f"   {label:<10} {entry.owner}/{entry.key}{detail}")
        return lines

    def _summary_entry(
        self, number: int, label: str, result: ScenarioResult
    ) -> list[str]:
        """Explain one scenario's boundary decision using only recorded evidence."""
        execution = result.read_execution
        call = execution.call
        protected = result.mode == "protected"
        policy = (
            "requester must equal target owner"
            if protected
            else "none — the owner field in model text is trusted"
        )
        if execution.decision == "block":
            decision = "BLOCK"
            why = (
                f"requester {result.requester!r} does not own the target namespace"
                f"{f' {call.owner!r}' if call is not None else ''}; "
                "the call was denied before storage was read"
            )
        elif result.leaked:
            decision = f"ALLOW — returned {execution.value!r}"
            why = (
                f"the executor ran the call as {call.owner!r} while the trusted "
                f"requester was {result.requester!r}"
                if call is not None
                else "the executor never compared requester to claimed owner"
            )
        elif call is None:
            decision = "NO DECISION"
            why = "no tool call reached the boundary"
        else:
            decision = execution.decision.upper()
            why = "the requester operated inside its own namespace"
        lines = [
            f"   {number}  {label}",
            *_wrap_field("Attack:", ATTACK_LABELS.get(result.attack, result.attack)),
            *_wrap_field("Orchestrator:", f"{result.orchestrator_hardening} prompt"),
            *_wrap_field("Executor policy:", policy),
        ]
        if call is not None:
            lines.extend(_wrap_field("Proposed call:", format_tool_call(call)))
        lines.extend(_wrap_field("Decision:", decision))
        if execution.reason:
            lines.extend(
                _wrap_field("Reason:", escape_terminal_controls(execution.reason))
            )
        lines.extend(_wrap_field("Why:", why))
        return lines

    @staticmethod
    def _forwarded_calls(result: ScenarioResult) -> int:
        """Count tool calls the orchestrator actually forwarded, from evidence."""
        return sum(
            1
            for line in result.orchestrator_output.splitlines()
            if line.strip().startswith("EXEC:")
        )

    def render_summary(
        self,
        vulnerable: ScenarioResult,
        protected: ScenarioResult,
        hardened_injection: ScenarioResult,
        naive_injection: ScenarioResult | None = None,
    ) -> list[str]:
        """Render a per-scenario breakdown of what each boundary decided and why."""
        stored = vulnerable.stored_value
        lines = [
            "",
            self.style("SUMMARY", "1;36"),
            "─" * WIDTH,
            *self._summary_entry(1, "Intentionally vulnerable", vulnerable),
            "",
            *self._summary_entry(2, "Protected (confused deputy)", protected),
            "",
            *self._summary_entry(3, "Protected + peer injection", hardened_injection),
            "",
            self.style("WHAT CHANGED", "1;36"),
            "─" * WIDTH,
            "   1 → 2  Same request and same model output; only the executor's",
            "          authorization check differs, and that flips leak to block.",
            "   2 → 3  The peer message now carries an injected [tool] line and",
            "          the orchestrator prompt is hardened.",
        ]
        if naive_injection is not None:
            forwarded_naive = self._forwarded_calls(naive_injection)
            forwarded_hardened = self._forwarded_calls(hardened_injection)
            lines.extend(
                [
                    f"          Same injection, forwarded tool calls: "
                    f"naive={forwarded_naive}, hardened={forwarded_hardened}",
                    "          → hardening dropped the injected instruction, so the",
                    "            prompt does measurably reduce what gets forwarded.",
                    f"          Executor decision: "
                    f"{naive_injection.read_execution.decision.upper()} (naive) / "
                    f"{hardened_injection.read_execution.decision.upper()} (hardened)",
                    "          → the peer's own proposal survives hardening; only",
                    "            authorization stops it reaching storage.",
                ]
            )
        if stored is not None:
            lines.extend(
                [
                    "",
                    f"   Data at risk in every run: client_a / secret = {stored!r}",
                ]
            )
        return lines

    def render(
        self,
        vulnerable: ScenarioResult,
        protected: ScenarioResult,
        hardened_injection: ScenarioResult,
        *,
        mode_notice: str,
        naive_injection: ScenarioResult | None = None,
    ) -> str:
        """Render the three-scenario comparison, plus any measured counterfactual."""
        vulnerable_outcome = "ALLOWED / LEAKED" if vulnerable.leaked else "NO LEAK"
        protected_outcome = (
            "BLOCKED / SAFE"
            if protected.read_execution.decision == "block"
            else "UNEXPECTED"
        )
        injection_outcome = (
            "BLOCKED / SAFE"
            if hardened_injection.read_execution.decision == "block"
            else "UNEXPECTED"
        )
        lines = [
            "╭" + "─" * (WIDTH - 2) + "╮",
            "│  MULTI-AGENT DATA SEGREGATION".ljust(WIDTH - 1) + "│",
            "│  Same request. Different enforcement boundary.".ljust(WIDTH - 1) + "│",
            "╰" + "─" * (WIDTH - 2) + "╯",
            "",
            self.style(mode_notice, "1;33"),
            self.render_scenario(1, vulnerable),
            self.render_scenario(2, protected),
            self.render_scenario(3, hardened_injection),
            "",
            self.style("COMPARISON", "1;36"),
            "─" * WIDTH,
            f"   {'Configuration':<36} Decision / outcome",
            f"   {'Intentionally vulnerable':<36} {vulnerable_outcome}",
            f"   {'Protected (confused deputy)':<36} {protected_outcome}",
            f"   {'Protected + peer injection':<36} {injection_outcome}",
            *self.render_summary(
                vulnerable, protected, hardened_injection, naive_injection
            ),
            "",
            "Prompt hardening helps; authorization at the executor is what holds.",
        ]
        return "\n".join(lines)

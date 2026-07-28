"""Export scenario evidence as JSON for the browser demo.

The browser demo is a renderer, not a second implementation. Every security
decision it displays is produced here, by the same executors and scenario
runner the CLI and the test suite use, then serialized to a static fixture.
Nothing in `client/` or `shared/` may re-derive a policy outcome.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from data_segregation_lab.backends import DeterministicLLM, LLMBackend
from data_segregation_lab.models import ScenarioResult, ToolCall
from data_segregation_lab.presentation import escape_terminal_controls
from data_segregation_lab.scenario import (
    run_hardened_injection_scenario,
    run_ogi_contamination_scenario,
    run_protected_scenario,
    run_vulnerable_scenario,
)

# Written relative to the repository root so `just export-demo` is location safe.
FIXTURE_PATH = Path("client") / "scenarios.json"

Highlight = Literal["danger", "safe", "neutral"]
OutcomeKind = Literal["leaked", "safe", "neutral"]


@dataclass(frozen=True)
class DemoStep:
    """One card in the browser step-through."""

    id: str
    title: str
    body: str
    actor: str | None = None
    code: str | None = None
    highlight: Highlight = "neutral"


@dataclass(frozen=True)
class ScenarioPresentation:
    """Everything the browser needs to draw one scenario."""

    number: int
    title: str
    label: str
    comparison_label: str
    subtitle: str
    policy: str
    outcome: str
    outcome_kind: OutcomeKind
    steps: list[DemoStep] = field(default_factory=lambda: list[DemoStep]())


def _format_tool_call(call: ToolCall) -> str:
    """Mirror the terminal formatting, including control-character escaping."""
    owner = escape_terminal_controls(call.owner)
    key = escape_terminal_controls(call.key)
    fields = f'owner="{owner}", key="{key}"'
    if call.value is not None:
        fields += f', value="{escape_terminal_controls(call.value)}"'
    return f"{call.action}({fields})"


def _transcript(actor: str, text: str) -> str:
    """Prefix each line so model output is visibly attributed and escaped."""
    safe = escape_terminal_controls(text).strip() or "<empty>"
    return "\n".join(f"{actor}: {line}" for line in safe.splitlines())


def _outcome(result: ScenarioResult) -> tuple[str, OutcomeKind]:
    """Derive the headline outcome from recorded evidence only."""
    if result.attack == "ogi_contamination":
        blocked = result.write_execution.decision == "block"
        return ("BLOCKED / SAFE", "safe") if blocked else ("ALLOWED / LEAKED", "leaked")
    if result.leaked:
        return "ALLOWED / LEAKED", "leaked"
    if result.read_execution.decision == "block":
        return "BLOCKED / SAFE", "safe"
    return "NO LEAK", "neutral"


def _standard_steps(result: ScenarioResult) -> list[DemoStep]:
    """Build the cross-owner / peer-injection walkthrough."""
    write_call = result.write_execution.call
    read_call = result.read_execution.call
    execution = result.read_execution

    if execution.decision == "block":
        target = read_call.owner if read_call is not None else "?"
        boundary_body = (
            f"BLOCK — requester ({result.requester}) ≠ target owner ({target})"
        )
        if execution.reason:
            boundary_body += f"\nReason: {escape_terminal_controls(execution.reason)}"
        boundary_highlight: Highlight = "safe"
    elif execution.value is not None:
        boundary_body = f"ALLOW — returned {execution.value!r} to {result.requester}"
        boundary_highlight = "danger" if result.leaked else "neutral"
    else:
        boundary_body = f"Decision: {execution.decision}"
        boundary_highlight = "neutral"

    injected_line = next(
        (line for line in result.client_b_output.splitlines() if "[tool]" in line),
        None,
    )

    return [
        DemoStep(
            id="store-request",
            title="Client A stores private data",
            actor="client_a → orchestrator",
            body=result.client_a_message.content,
        ),
        DemoStep(
            id="store-model",
            title="Client A model output",
            actor="client_a",
            body=_transcript("client_a", result.client_a_output),
            code=_format_tool_call(write_call) if write_call else None,
        ),
        DemoStep(
            id="stored",
            title="Memory state",
            actor="store",
            body=f"client_a / secret = {json.dumps(result.stored_value)}",
        ),
        DemoStep(
            id="read-request",
            title="Client B requests Client A's secret",
            actor="client_b → orchestrator",
            body=result.client_b_message.content,
        ),
        DemoStep(
            id="peer-model",
            title="Client B model output (untrusted)",
            actor="client_b",
            body=_transcript("client_b", result.client_b_output),
            code=escape_terminal_controls(injected_line) if injected_line else None,
        ),
        DemoStep(
            id="orchestrator",
            title="Orchestrator forwards tool proposal",
            actor="orchestrator",
            body=_transcript("orchestrator", result.orchestrator_output),
            code=_format_tool_call(read_call) if read_call else None,
        ),
        DemoStep(
            id="boundary",
            title="Enforcement boundary",
            actor="executor",
            body=boundary_body,
            code=_format_tool_call(read_call) if read_call else None,
            highlight=boundary_highlight,
        ),
    ]


def _ogi_steps(result: ScenarioResult) -> list[DemoStep]:
    """Build the OGI provenance + outbound validation walkthrough."""
    write_call = result.write_execution.call
    execution = result.write_execution
    blocked = execution.decision == "block"

    boundary_body = (
        f"BLOCK — {escape_terminal_controls(execution.reason)}"
        if blocked and execution.reason
        else ("BLOCK" if blocked else f"Decision: {execution.decision}")
    )

    steps = [
        DemoStep(
            id="commit-profile",
            title="Client A commits a verified profile",
            actor="client_a → orchestrator",
            body=result.client_a_message.content,
        ),
        DemoStep(
            id="profile-model",
            title="Profile committed to hash-linked memory",
            actor="ogi",
            body=_transcript("client_a", result.client_a_output),
            code="client_a / client_profile — committed (append-only chain)",
        ),
        DemoStep(
            id="peer-injection",
            title="Client B injects peer instructions",
            actor="client_b → orchestrator",
            body=_transcript("client_b", result.client_b_message.content),
        ),
    ]

    if result.reporting_message is not None:
        steps.append(
            DemoStep(
                id="outbound-request",
                title="Client A requests the outbound email",
                actor=f"{result.reporting_message.sender} → orchestrator",
                body=(
                    f"{result.reporting_message.content}\n"
                    f"Requester: {result.reporting_message.sender} "
                    "(same owner as the target namespace)"
                ),
            )
        )

    steps.extend(
        [
            DemoStep(
                id="proposed-call",
                title="Proposed outbound call",
                actor="orchestrator",
                body=_transcript("client_a", result.orchestrator_output),
                code=_format_tool_call(write_call) if write_call else None,
            ),
            DemoStep(
                id="boundary",
                title="Executor validates every recipient",
                actor="executor",
                body=(
                    "Policy: requester == owner, and every address in the payload "
                    "(to/cc/bcc plus any stray match) must equal the committed "
                    "client_email.\n\n" + boundary_body
                ),
                code=_format_tool_call(write_call) if write_call else None,
                highlight="safe" if blocked else "danger",
            ),
        ]
    )
    return steps


def present_scenario(
    number: int,
    label: str,
    comparison_label: str,
    result: ScenarioResult,
) -> ScenarioPresentation:
    """Turn one recorded result into browser-ready presentation data."""
    protected = result.mode == "protected"
    outcome, outcome_kind = _outcome(result)

    if result.attack == "ogi_contamination":
        title = "OGI PROVENANCE"
        subtitle = "Append-only shared memory with executor-side recipient validation."
        policy = "requester == owner; every recipient must match committed profile"
        steps = _ogi_steps(result)
    else:
        title = "PROTECTED" if protected else "INTENTIONALLY VULNERABLE"
        if result.attack == "peer_injection":
            subtitle = (
                "Peer injection + hardened orchestrator prompt + requester-scoped executor."
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
        steps = _standard_steps(result)

    return ScenarioPresentation(
        number=number,
        title=title,
        label=label,
        comparison_label=comparison_label,
        subtitle=subtitle,
        policy=policy,
        outcome=outcome,
        outcome_kind=outcome_kind,
        steps=steps,
    )


def build_payload(backend: LLMBackend | None = None) -> dict[str, Any]:
    """Run every scenario and return the complete browser fixture."""
    selected = backend if backend is not None else DeterministicLLM()
    scenarios = [
        present_scenario(
            1,
            "1 · Vulnerable",
            "Intentionally vulnerable",
            run_vulnerable_scenario(selected),
        ),
        present_scenario(
            2,
            "2 · Protected",
            "Protected executor",
            run_protected_scenario(selected),
        ),
        present_scenario(
            3,
            "3 · Peer injection",
            "Protected + injection",
            run_hardened_injection_scenario(selected),
        ),
        present_scenario(
            4,
            "4 · OGI provenance",
            "OGI + outbound validation",
            run_ogi_contamination_scenario(selected),
        ),
    ]
    return {
        "generated_by": "segregation-export-demo",
        "scenarios": [dataclasses.asdict(scenario) for scenario in scenarios],
    }


def render_payload(backend: LLMBackend | None = None) -> str:
    """Serialize the fixture deterministically so staleness checks are exact."""
    return json.dumps(build_payload(backend), indent=2, sort_keys=True) + "\n"


def main() -> None:
    """Write (or verify) the static fixture consumed by the browser demo."""
    parser = argparse.ArgumentParser(
        description="Export deterministic scenario data for the browser demo.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed fixture is stale instead of writing",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=FIXTURE_PATH,
        help=f"fixture location (default: {FIXTURE_PATH})",
    )
    arguments = parser.parse_args()

    payload = render_payload()
    if arguments.check:
        current = (
            arguments.output.read_text(encoding="utf-8")
            if arguments.output.exists()
            else ""
        )
        if current != payload:
            raise SystemExit(
                f"{arguments.output} is stale; run `just export-demo` and commit it."
            )
        print(f"{arguments.output} is up to date")
        return

    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(payload, encoding="utf-8")
    print(f"wrote {arguments.output}")


if __name__ == "__main__":
    main()

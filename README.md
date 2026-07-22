# Data-Segregation Failures in Multi-Agent LLM Systems

> [!CAUTION]
> **Intentionally vulnerable educational project.** The vulnerable scenario
> deliberately omits a read-authorization check to demonstrate cross-agent
> data leakage. It uses synthetic, in-memory data and a deterministic fake
> model by default. Do not deploy the vulnerable path or connect it to
> production data.

## What this repository demonstrates

Three minimal agents—Client A, Client B, and an orchestrator—share a memory
store inside a synthetic regulated-workspace simulation. Client B asks the
orchestrator to read Client A's secret:

- `VulnerableToolExecutor` trusts the model-selected owner and leaks.
- `OwnerScopedToolExecutor` binds that owner to the requester and blocks.
- A third scenario adds **peer instruction injection** plus a **hardened
  orchestrator prompt** — the protected executor still blocks the leak.

The vulnerable and corrected paths live side by side so the enforcement
boundary is easy to compare. See [THREAT_MODEL.md](THREAT_MODEL.md) for the
security invariant, trust boundaries, and explicit scope. See
[PLAYBOOK.md](PLAYBOOK.md) for how the pillars map to multi-agent agent
security in regulated environments.

**Companion project:** [Capability Wall](https://github.com/DoctorKhan/capability-wall) — browser
prompt-injection CTF with constrained action schemas and adversarial output
validation (`sanitizeDecision`). Capability Wall covers untrusted **context**; this lab covers untrusted **tools and tenancy**.

## Quick start

Install the locked dependencies:

```bash
uv sync
```

Run the deterministic, offline comparison:

```bash
just demo
```

Expected conclusion:

```text
Vulnerable           ALLOWED / LEAKED
Protected            BLOCKED / SAFE
Protected + peer injection   BLOCKED / SAFE
```

Reproduce only the intentional vulnerability test:

```bash
just reproduce-vulnerability
```

Run every local quality and behavior check:

```bash
just check
```

Run a compact, repeated comparison (500 fresh runs per policy by default):

```bash
just repetitions
just repetitions --repetitions 25
```

## Code organization

The package uses a `src/` layout so each responsibility has one home:

```text
src/data_segregation_lab/
├── models.py          # messages, tool calls, and structured results
├── protocol.py        # inter-agent message envelope + untrusted labeling
├── prompts.py         # orchestrator hardening tiers (prompt defense alone fails)
├── ownership.py       # intelligence ownership registry (synthetic tenant metadata)
├── backends.py        # deterministic and opt-in OpenRouter adapters
├── tool_protocol.py   # fail-closed parsing + sanitize_tool_call boundary
├── storage.py         # storage protocol and in-memory implementation
├── executors.py       # intentionally vulnerable and protected policies
├── scenario.py        # shared orchestration flow (3 scenario variants)
├── presentation.py    # terminal-safe rendering only
├── cli.py             # narrated demo entry point
└── batch.py           # deterministic repetition entry point
```

Tests are split along the same boundaries. Both CLIs and all end-to-end tests
use `ScenarioRunner`; the presentation module never executes storage operations.

## Explicit OpenRouter mode

OpenRouter calls are optional and never selected automatically. Copy the
credential template, add your own ignored key, and use the separate command:

```bash
cp .env.example .env.openrouter
just demo-openrouter
```

`demo-openrouter` can incur API charges and is intentionally excluded from CI.
Network requests use verified TLS. Never commit `.env.openrouter` or a real API
key.

## Repository safety boundary

| Intentionally vulnerable | Kept secure |
| --- | --- |
| Missing owner check in `VulnerableToolExecutor` | TLS validation |
| Cross-owner read in synthetic memory | Credential and dotenv handling |
| Deterministic exploit assertion | Default and CI execution |
| Model-selected target owner | Terminal rendering of model output |

The parser, model harness, and in-memory store remain intentionally minimal and
are not production components. New vulnerability scenarios should each state
one invariant, reproduce one bounded defect, provide a mitigation beside it,
and use only synthetic data.

## Reporting unintended vulnerabilities

The demonstrated cross-owner read is expected behavior. Please report unrelated
security problems according to [SECURITY.md](SECURITY.md), preferably through
GitHub private vulnerability reporting rather than a public issue.

## GitHub maintainer setup

After publishing the repository, configure these hosted protections in GitHub:

- Enable private vulnerability reporting under **Settings → Security**.
- Enable secret scanning and push protection under **Settings → Advanced
  Security**.
- Protect the default branch and require the `Vulnerability Lab CI / Verify
  lab` check before merge.
- Keep Actions workflow permissions read-only unless a future job has a
  documented need for additional access.

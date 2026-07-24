# Threat Model

## Purpose

This repository is a bounded educational lab for one application-logic flaw:
an orchestrator acting as a confused deputy when it trusts a model-selected
data owner. It is not a deployable agent platform or storage service.

## Security invariant

An authenticated requester may read only data owned by that requester:

```text
allow read when requester == owner; otherwise deny
```

The requester identity is trusted execution context. The owner, key, value,
prompt, message content, and all LLM output are untrusted.

## Assets

- Per-owner values stored in `InMemoryStore`
- The integrity of authorization decisions
- OpenRouter credentials used only by the opt-in Python CLI (`just demo-openrouter`); the GitHub Pages browser demo is fully offline and never calls OpenRouter
- Terminal and CI output

## Trust boundaries

```text
user/peer message
       ↓ untrusted (protocol labels sender; body is never an auth grant)
LLM output and tool arguments
       ↓ schema parsing + sanitize_tool_call
orchestrator policy boundary (requester == owner)
       ↓ authorized operation only
InMemoryStore
```

Inter-agent messages use a trusted envelope (`Participant.send` assigns
`sender`) and untrusted bodies (`protocol.format_messages_for_context`).
Peer instruction injection is modeled in scenario 3: hardened prompts may
still produce a cross-owner tool proposal; the executor must default-deny.

`DeterministicLLM` is treated as untrusted because it represents the same
boundary as a network model. `OpenRouterLLM`, OpenRouter responses, and peer
agent messages are never authorization authorities.

## Intentional vulnerability

`VulnerableToolExecutor` passes `call.owner` directly to the store. Client B can
cause the orchestrator to read Client A's namespace because no comparison is
made against the trusted requester. It would also allow cross-owner writes;
that integrity risk is covered by a focused executor test. The vulnerability
is local, uses the synthetic value `42`, and has no persistence or external
victim.

The vulnerability test is marked `intentional_vulnerability`; it passes only
when the documented leak is reproduced. This is expected lab behavior, not an
unnoticed regression.

## Mitigation

`OwnerScopedToolExecutor` checks `requester == owner` before every read or write
and defaults to denial. The paired mitigation tests prove that the same request
is blocked before the store is touched.

## Safety controls

- `just demo` always uses `DeterministicLLM`, regardless of environment variables.
- `just demo-openrouter` is the only command that loads `.env.openrouter`.
- CI has read-only repository permission, receives no OpenRouter secret, and
  executes only the deterministic path.
- TLS verification remains enabled for live requests.
- Raw model control characters are escaped before terminal rendering.
- Local credential files are ignored; `.env.example` contains placeholders.
- All demonstrated identities, keys, and values are synthetic.

## Out of scope

This lab does not claim to implement production-grade authentication,
authorization, durable storage, audit logging, quotas, transactional updates,
or a hardened tool-call schema. Those omissions must not be copied into a real
system. They should become separate, explicitly documented scenarios if the
repository is expanded.

## Adding another scenario

Every new vulnerability demonstration must:

1. State one security invariant and one intentional violation.
2. Use synthetic local data and avoid third-party targets.
3. Provide vulnerable and protected paths side by side.
4. Add one test that reproduces the defect and one that proves the mitigation.
5. Keep network use opt-in and out of CI.
6. Document what is intentionally vulnerable and what remains protected.

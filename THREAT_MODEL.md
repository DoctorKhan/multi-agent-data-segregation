# Threat Model

## Purpose

This repository is a bounded educational lab for multi-agent tenancy failures
in regulated workspaces. It is not a deployable agent platform or storage
service. Two primary scenarios are documented:

1. **Confused deputy** — an orchestrator trusts a model-selected data owner.
2. **OGI contamination** — an agent proposes outbound email to an unverified
   primary recipient despite peer injection and a committed tenant profile.

## Security invariants

### Tenancy (scenarios 1–3)

An authenticated requester may read or write only data owned by that requester:

```text
allow read/write when requester == owner; otherwise deny
```

The requester identity is trusted execution context. The owner, key, value,
prompt, message content, and all LLM output are untrusted.

### Outbound email lineage (scenario 4 — OGI prototype)

For `email_action` writes, the executor must validate the proposed primary
recipient (`to`) against the **committed** tenant profile before any OGI
commit:

```text
allow email_action write when requester == owner
  and proposed_to == committed_client_profile.client_email; otherwise deny
```

Only **committed** OGI entries are readable. Proposed or anomalous entries are
ignored by agents. Cross-owner reads and writes default-deny at the executor.

## Assets

- Per-owner values stored in `InMemoryStore`
- OGI append-only provenance chain (`OGIClient`) with hash-linked entries
- Committed tenant profile metadata (`client_profile` JSON with `client_email`)
- The integrity of authorization and outbound-routing decisions
- OpenRouter credentials used only by the opt-in Python CLI (`just demo-openrouter`); the GitHub Pages browser demo is fully offline and never calls OpenRouter
- Terminal and CI output

## Trust boundaries

### Confused-deputy path (scenarios 1–3)

```text
user/peer message
       ↓ untrusted (protocol labels sender; body is never an auth grant)
LLM output and tool arguments
       ↓ schema parsing + sanitize_tool_call
orchestrator policy boundary (requester == owner)
       ↓ authorized operation only
InMemoryStore
```

### OGI path (scenario 4)

```text
user/peer message
       ↓ untrusted
LLM output and tool arguments
       ↓ schema parsing + sanitize_tool_call
OGIProvenanceExecutor
       ↓ requester == owner
       ↓ email_action: verify primary recipient vs committed client_profile
       ↓ propose → commit (hash-linked chain) or anomaly
InMemoryStore (mirror of committed values)
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

## Mitigations

`OwnerScopedToolExecutor` checks `requester == owner` before every read or write
and defaults to denial. The paired mitigation tests prove that the same request
is blocked before the store is touched.

`OGIProvenanceExecutor` adds:

- Append-only hash-linked provenance (`propose` / `commit` / `anomaly`)
- Reads only from committed OGI entries
- Executor-side outbound validation for `email_action` writes against committed
  `client_profile` data
- Cross-owner default-deny and unverified-primary-recipient blocking **before**
  commit

Run the OGI scenario:

```bash
just demo-ogi
```

## Safety controls

- `just demo` and `just demo-ogi` always use `DeterministicLLM`, regardless of environment variables.
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
BCC/CC validation on outbound email, or a hardened tool-call schema. Those
omissions must not be copied into a real system. They should become separate,
explicitly documented scenarios if the repository is expanded.

The OGI layer is a **prototype** illustrating provenance and outbound
validation patterns — not a production shared-memory service.

## Adding another scenario

Every new vulnerability demonstration must:

1. State one security invariant and one intentional violation.
2. Use synthetic local data and avoid third-party targets.
3. Provide vulnerable and protected paths side by side.
4. Add one test that reproduces the defect and one that proves the mitigation.
5. Keep network use opt-in and out of CI.
6. Document what is intentionally vulnerable and what remains protected.

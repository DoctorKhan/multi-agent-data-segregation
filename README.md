# Data-Segregation Failures in Multi-Agent LLM Systems

> [!CAUTION]
> **Intentionally vulnerable educational project.** This repository demonstrates
> a bounded application-logic flaw in multi-agent LLM systems. It uses synthetic,
> in-memory data and a deterministic offline model by default. Do not deploy the
> vulnerable path or connect it to production data.

## The problem

When several agents share tools and memory inside a regulated workspace, the
orchestrator can become a **confused deputy**: it executes a model-proposed read
or write against the wrong tenant because authorization lives in prompt reasoning
instead of at execution.

**Security invariant:**

```text
allow when requester == owner; otherwise deny
```

The requester identity is trusted execution context. Every message body, prompt
fragment, and model/tool proposal is untrusted.

## Documentation

- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, trust boundaries, intentional vulnerability, mitigations
- [SECURITY.md](SECURITY.md) — reporting unintended issues and lab safety controls

## Status

This repository is an educational lab, not a deployable agent platform. Runnable
demonstrations and tests land in subsequent commits.

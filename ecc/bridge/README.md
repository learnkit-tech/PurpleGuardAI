# ECC bridge — PurpleGuard ↔ ECC snapshot

`ecc/bridge/` is the **only** surface PurpleGuard imports from the ECC snapshot. Nothing outside
this package may import deeper into `ecc/`.

It has two layers, both speaking the same contract primitives (deterministic `task_id` /
`correlation_id`, structured results, explicit structured errors).

## 1. Runtime capabilities — `EccBridge`

```python
from ecc.bridge import EccBridge
bridge = EccBridge()
bridge.submit_task("ecc.snapshot.catalog")   # real curated-snapshot registry
bridge.submit_task("ecc.harness.describe")   # real [harness_runners.purpleguard] contract
bridge.submit_task("agent.evaluate", input={"output": "..."})   # real ECC evaluator
bridge.submit_task("ecc2.session.start")     # honest ECC_UNAVAILABLE (no cargo/rustc)
```

- Supports: `ecc.runtime.status`, `ecc.snapshot.catalog`, `ecc.harness.describe`,
  `agent.evaluate`, `integration.aura.trust_check`.
- Unavailable capabilities return `ECC_UNAVAILABLE`; unknown operations return
  `ECC_UNSUPPORTED_OPERATION`. Nothing is faked.
- Execution is **synchronous**; `get_task_status`/`get_task_result` read a small in-memory cache —
  this is not an async job system, and it is documented as such.

## 2. Security Agent Workforce — now PurpleGuard-native

The agent workforce is **no longer part of `ecc/bridge/`**. It is a PurpleGuard-native subsystem at
`security_workforce/` (see `security_workforce/README.md`), which adapts the audited ECC agent
knowledge into PurpleGuard's own capability. It imports **no** ECC internals.

```python
from security_workforce import WorkforceOrchestrator
workforce = WorkforceOrchestrator()
outcome = workforce.run("security.review", target="/path/to/project")
```

The two layers still share the same contract primitives (deterministic `task_id` /
`correlation_id`, structured results, explicit structured errors). `ecc/bridge/` covers *runtime
capabilities* of the snapshot; `security_workforce/` covers the *agent workforce*.

See `docs/ECC_AGENT_WORKFORCE.md` for the role mapping, permission model, context/memory model,
evaluation/correlation model, orchestrator design, and continuous-assessment plan.

## Design constraints

- **Thin and explicit.** No arbitrary ECC internals leak into PurpleGuard.
- **PurpleGuard authoritative.** Security execution stays in `scanner/`, `hacker/`,
  `purpleguard_runner.py`; the bridge never grants approval.
- **No porting.** `ecc2/` is reached by building/invoking it, not by translating it.
- **Fail-closed.** Unavailable capability or malformed input is an explicit error, never a silently
  successful state.
- **Additive.** Existing PurpleGuard behavior keeps working when the bridge is absent.

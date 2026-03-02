# Suy Sideguy

Runtime safety guard for autonomous agents.

Suy Sideguy watches a running agent process and decides whether actions should be **SAFE**, **FLAGGED**, or **KILLED** based on your policy.

> OSS companion to **Hermes Warden**.

---

## What this tool is (and is not)

### ✅ What it does
- Watches process, file, and network behavior for an agent process
- Applies policy rules (optionally with a local LLM judge via Ollama)
- Can terminate severe violations with `SIGKILL` when policy requires it
- Stores evidence and can generate incident-ready forensic reports

### ⚠️ What it does not do
- It is **not kernel-level enforcement** (it runs in userspace)
- File visibility via `psutil.open_files()` is best-effort and OS-dependent
- Network checks are based on observed remote IP/port; domain matching can be lossy after DNS

---

## Relationship to Little Canary

- **Little Canary** protects the **input side** (prompt-injection sensing)
- **Suy Sideguy** protects the **runtime/output side** (containment + forensics)

Use both for defense in depth.

---

## Install

```bash
pip install suy-sideguy
```

Requires Python 3.9+.

For development:

```bash
git clone https://github.com/roli-lpci/suy-sideguy.git
cd suy-sideguy
pip install -e ".[dev]"
```

---

## 5-minute quickstart

### 1) Choose target process
Use one of:
- `--agent-pid` (recommended for production)
- `--agent-name` (convenient, but can match unintended processes)

### 2) Start from the example policy scope
- Open `examples/scope.openclaw.yaml`
- For staged rollout, start with `examples/scope.low-disruption.yaml`
- Narrow allowlists to only what your workload truly needs

### 3) Run the warden

```bash
# Safer targeting: PID
suy-warden --scope examples/scope.openclaw.yaml --agent-pid 12345 --poll 0.5

# Convenience targeting: process name
suy-warden --scope examples/scope.openclaw.yaml --agent-name openclaw --poll 0.5
```

### 4) Generate report after a run

```bash
suy-forensic-report --last-hours 24
```

---

## Where logs and evidence go

Default paths:

- `~/.local/share/sysmond/warden.log`
- `~/.local/share/sysmond/logs/actions_*.jsonl`
- `~/.local/share/sysmond/logs/incidents/*.json`

Tip: treat these as security artifacts. Protect access and define retention/rotation.

---

## Recommended rollout strategy

1. **Audit-first**: observe and tune policy without auto-kill pressure.
2. **Confirm mode** for ambiguous events.
3. **Enforce mode** only after your hard invariants are validated.

---

## Important safety caveats

- `SIGKILL` is immediate and can interrupt legitimate work if policy is too broad.
- Name matching (`--agent-name`) can over-match; prefer PID targeting in production.
- This project should be one part of a layered defense strategy.

## Expected flag noise (early rollout)

Early flag noise is normal during policy calibration on real workloads.

- Treat early `FLAG` events as calibration data, not immediate defects.
- Use policy thresholds (`flag_threshold`, `flag_window`) to control when accumulated risk escalates to kill.
- Keep **hard invariants** (e.g., forbidden secrets paths / destructive commands) as immediate stop conditions.
- Start in audit-first mode, then tighten only after reviewing forensic logs.

---


## Release quality status

_Current status based on repository checks and CI configuration; not a formal security certification._


- ✅ Tests in repo (`pytest`)
- ✅ Package buildable (`python -m build`)
- ✅ CI workflow (`.github/workflows/ci.yml`)
- ✅ Publish workflow (`.github/workflows/publish.yml`)
- ✅ Security disclosure policy (`SECURITY.md`)

## Development

```bash
pip install -e .[dev]
pytest
```

Also see:
- `CONTRIBUTING.md`
- `SECURITY.md`
- `PUBLISH_CHECKLIST.md`
- `AGENTS.md`
- `CODE_OF_CONDUCT.md`
- Audit checklist: `docs/AUDIT_CHECKLIST.md`
- Layered plan: `docs/IMPLEMENTATION_PLAN_LAYERED.md`
- Internal reviews: `docs/internal/`

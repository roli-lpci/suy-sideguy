# AGENTS.md — Quick Navigation for Human + AI Maintainers

This file is a fast map for contributors and coding agents.

## Repo purpose
Suy Sideguy is a runtime safety guard for autonomous agent processes.

## Start here
- `README.md` — install, quickstart, rollout model
- `examples/scope.openclaw.yaml` — baseline policy
- `examples/scope.low-disruption.yaml` — safer staged rollout profile
- `docs/IMPLEMENTATION_PLAN_LAYERED.md` — current roadmap/checklist
- `docs/AUDIT_CHECKLIST.md` — promotion gate checks

## Core code
- `suy_sideguy/warden.py` — runtime observation/evaluation/enforcement loop
- `suy_sideguy/forensic_report.py` — evidence aggregation and report export

## Testing and packaging
- `tests/` — regression tests
- `pyproject.toml` — package metadata + entry points
- CI: `.github/workflows/ci.yml`
- Publish: `.github/workflows/publish.yml`

## Contract boundaries
- Inbound prompt-defense belongs to Little Canary.
- Runtime/output enforcement belongs to Suy Sideguy.

## Contribution expectations
- Keep changes minimal and auditable.
- Prefer policy/config additions before invasive enforcement changes.
- Any kill-path change should include tests + forensic-output validation.

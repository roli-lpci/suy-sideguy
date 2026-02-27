# Publish Checklist — suy-sideguy

## Pre-release essentials

- [ ] Confirm version in `pyproject.toml` (and tag plan) is correct
- [ ] `python -m venv .venv && source .venv/bin/activate`
- [ ] `pip install -U pip`
- [ ] `pip install -e '.[dev]'`
- [ ] `pytest` passes
- [ ] `python -m suy_sideguy.warden --help` works
- [ ] `python -m suy_sideguy.forensic_report --help` works

## Documentation

- [ ] README reflects current CLI and behavior
- [ ] Security caveats are accurate and explicit
- [ ] `CONTRIBUTING.md` present and current
- [ ] `SECURITY.md` present with private reporting guidance
- [ ] LICENSE present and correct

## Packaging sanity

- [ ] `python -m pip install build`
- [ ] `python -m build` succeeds
- [ ] Verify wheel/sdist include package + docs expected for release
- [ ] Validate console entry points:
  - [ ] `suy-warden --help`
  - [ ] `suy-forensic-report --help`

## Security/reliability checks

- [ ] Scope example reviewed for least privilege
- [ ] Confirm docs recommend `--agent-pid` for production use
- [ ] Confirm logs path/retention strategy documented for operators
- [ ] Confirm kill semantics (`SIGKILL`) are explicit in docs

## Repo hygiene

- [ ] `.gitignore` excludes virtualenv/build/log artifacts
- [ ] No secrets or private logs in git history/staging
- [ ] `git status` clean except intentional release changes

## Release step

- [ ] Commit with release-prep message
- [ ] Tag release (e.g., `v0.1.0-alpha.1`)
- [ ] Publish release notes with known limitations

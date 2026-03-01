# README & Docs Readability Review

Date: 2026-02-27  
Reviewer: Docs/readability subagent

## Scope reviewed
- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `examples/scope.openclaw.yaml` (context only)
- Repo documentation surface (no files currently under `docs/`)

---

## Executive summary

The project is technically solid but originally had onboarding friction for non-expert users:
- value proposition was clear, but not explained in plain language up front,
- first-run path lacked a beginner-friendly sequence,
- caveats were present but easy to miss,
- docs used concise maintainer language more than operator language.

I rewrote key docs to reduce ambiguity while preserving technical accuracy.

---

## Concrete improvements made

## 1) `README.md` rewritten for first-time operators

### What changed
- Added plain-language opener ("what it is / what it is not")
- Added explicit expectations with ✅/⚠️ sections
- Reframed quickstart as a 5-minute step-by-step flow
- Made `--agent-pid` recommendation clearer and earlier
- Pulled artifact/log paths into a dedicated section
- Kept rollout guidance but made it more actionable for non-experts
- Consolidated caveats into a high-visibility safety section

### Why this helps
- Reduces cognitive load for users unfamiliar with process monitoring
- Minimizes accidental risky deployment (name matching, aggressive kill policy)
- Improves scanability (users can find setup/run/report paths quickly)

---

## 2) `CONTRIBUTING.md` simplified and action-oriented

### What changed
- Tightened setup/check commands into a predictable sequence
- Clarified PR expectations with explicit quality gates
- Added security-sensitive issue routing note to `SECURITY.md`

### Why this helps
- Makes contribution path clearer for occasional contributors
- Reduces back-and-forth over missing tests/docs/security details

---

## 3) `SECURITY.md` made more operator-friendly

### What changed
- Improved vulnerability-reporting wording for clarity
- Reframed hardening guidance as an operator checklist
- Kept all original security intent and technical constraints

### Why this helps
- Better for real-world deployment handoff
- Easier for non-security specialists to follow correctly

---

## Remaining recommendations (not yet applied)

1. **Add `docs/` onboarding pages** (repo currently has no docs files there):
   - `docs/ONBOARDING.md`: install, first run, expected outputs, troubleshooting
   - `docs/POLICY_TUNING.md`: audit→confirm→enforce with concrete examples

2. **Add a “Troubleshooting” section to README**:
   - target process not found
   - no logs generated
   - false positives causing unintended kills

3. **Include one annotated sample incident**:
   - show one `actions_*.jsonl` event and one incident JSON with field explanations

4. **Add terminology mini-glossary**:
   - “scope”, “invariant”, “confirm mode”, “enforce mode”, “forensic artifact”

5. **Cross-link docs from release artifacts**:
   - ensure PyPI long description points to onboarding and security sections clearly

---

## Readability risk areas to watch as project grows

- As policy capabilities expand, avoid burying behavior-changing defaults.
- Keep security caveats near command examples (not only at the bottom).
- Prefer explicit examples over abstract warning text.

---

## Files edited in this pass

- `README.md` (major rewrite for onboarding clarity)
- `CONTRIBUTING.md` (clarified contribution path)
- `SECURITY.md` (clarified reporting + hardening checklist)
- `README_READABILITY_REVIEW.md` (this report)

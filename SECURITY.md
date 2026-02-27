# Security Policy

## Supported versions

Current support target: latest `main` branch and newest tagged release.

## Reporting a vulnerability

Please **do not** open public issues for suspected vulnerabilities.

Preferred process:
1. Email the maintainer directly (or use a private GitHub Security Advisory, if enabled).
2. Include reproduction steps, expected impact, and any known mitigation.
3. You should receive acknowledgment as soon as possible.

## Operator hardening checklist

Before production use:
- Start in audit-first mode and validate policy against real workloads.
- Prefer `--agent-pid` over process-name matching.
- Keep scope allowlists narrow and explicit.
- Store logs on protected storage and define rotation/retention.
- Pair with inbound protections (for example, Little Canary) for layered defense.

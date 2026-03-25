# Security Policy

## Supported Versions

Security fixes are expected to land in:
- the latest public `main` branch
- the latest tagged public release, when tags exist

Older snapshots may not receive fixes.

## Reporting a Vulnerability

If you believe you have found a security issue in Splunk Utility Tool:

1. Do **not** open a public issue with sensitive exploit details.
2. Prefer GitHub security reporting if enabled for the repository.
3. Otherwise, contact **Gabriel (Skyredt)** through GitHub:
   - https://github.com/Skyredt

## What to Include

Please include:
- affected version or commit
- a short description of the issue
- impact assessment
- steps to reproduce
- whether credentials, tokens, or local files are involved
- sanitized logs or screenshots if useful

## Response Expectations

This project will try to:
- acknowledge reports in a reasonable timeframe
- reproduce and validate the issue
- prepare a fix or mitigation where appropriate
- publish a coordinated fix summary when possible

## Scope Notes

This repository is intended to remain free of:
- live credentials
- local runtime state
- secret files
- deployment-specific internal environment data

If you discover a file or example value that appears sensitive or environment-specific, please report it as a security or privacy concern.

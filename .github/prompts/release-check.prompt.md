---
description: "Run a release-readiness check for this Windows WPF app by restoring, building, publishing, and summarizing outcomes with actionable fixes."
name: "Release Readiness Check"
argument-hint: "Optional focus, for example: publish only, CI parity, or packaging validation"
agent: "agent"
---
Perform a release-readiness check for this repository.

Scope:
- Use the optional user argument as focus guidance if provided. Otherwise run full validation.
- Validate commands from [project instructions](../copilot-instructions.md) and [CI workflow](../workflows/ci.yml).

Required checks:
1. Run restore.
2. Run a debug project build from repo root.
3. Run CI parity build using no-restore.
4. Run release single-file publish for win-x64.

Report format:
1. Overall status: pass or fail.
2. Command results table with command, outcome, and key output lines.
3. If failures exist, provide the top root cause and a minimal fix plan.
4. If all checks pass, list produced output artifacts and paths.

Constraints:
- Do not change source files unless explicitly asked.
- Keep the summary concise and actionable.

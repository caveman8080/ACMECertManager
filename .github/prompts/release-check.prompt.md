---
description: "Run a release-readiness check for this Windows WPF app by restoring, building, publishing, and summarizing outcomes with actionable fixes."
name: "Release Readiness Check"
argument-hint: "Optional focus, for example: publish only, CI parity, or packaging validation"
agent: "agent"
---
Perform a release-readiness check for this repository.

Scope:
- Use the optional user argument only to prioritize the summary and any extra notes; always run the required checks below.
- Extract the specific CLI arguments and flags from [project instructions](../copilot-instructions.md) and [CI workflow](../workflows/ci.yml), and use them when executing the required checks. If either file cannot be found, proceed with standard `dotnet` CLI commands.

Required checks:
1. Run restore.
2. Run a debug project build from repo root.
3. Run CI parity build using no-restore.
4. Run release single-file publish for win-x64.

If a check fails, abort immediately and do not run subsequent checks.

Report format:
1. Overall status: pass or fail.
2. Command results table with command, outcome, and key output lines.
3. If failures exist, provide the top root cause and a minimal fix plan.
4. If all checks pass, list produced output artifacts and paths.

Constraints:
- Do not change source files unless explicitly asked.
- Keep the summary concise and actionable.

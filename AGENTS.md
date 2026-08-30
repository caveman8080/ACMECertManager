# Agent instructions

This file is for coding agents working in ACMECertManager. Humans remain in charge.

## Authority and git

- The human maintainer (`caveman8080`) is the final approver for every change.
- Never push `main`. Work on a topic branch and open a pull request.
- Do not merge PRs.

## Which agent

- The coding agent for this repository is **Grok Build**, run via yard jobs.
- Do not use GitHub Copilot coding agent here unless the captain names this repo and the specific task.

## Style and dependencies

- Match existing C# / WPF style in `src/` (nullable reference types, async/await, service vs. code-behind split).
- Do not add NuGet packages unless a human has approved them.

## Read these first

- [README.md](README.md) — product behavior and user-facing docs
- [CONTRIBUTING.md](CONTRIBUTING.md) — local build, test, and PR process
- [SECURITY.md](SECURITY.md) — private vulnerability reporting
- [.github/copilot-instructions.md](.github/copilot-instructions.md) — architecture and code-style notes for agents

Do not copy CONTRIBUTING.md into this file. Follow it instead.

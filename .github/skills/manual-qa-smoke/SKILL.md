---
name: manual-qa-smoke
description: 'Manual smoke test workflow for ACMECertManager. Use for pre-release validation of launch, staging issuance flow, certificate persistence, and theme persistence.'
argument-hint: 'Optional scope such as launch-only, issuance-only, or full-smoke'
user-invocable: true
---

# Manual QA Smoke

## When to Use
- Validate app behavior before release when no automated tests are available.
- Re-check core functionality after changes in [AcmeService.cs](../../../src/AcmeService.cs), [MainWindow.xaml.cs](../../../src/MainWindow.xaml.cs), [CertificateStorage.cs](../../../src/CertificateStorage.cs), or [App.xaml.cs](../../../src/App.xaml.cs).
- Confirm Windows-specific behaviors such as port 80 challenge handling assumptions.

## Procedure
1. Build the app in Debug mode.
2. Launch the app and confirm the dashboard loads without errors.
3. Verify issue flow defaults to staging mode and blocks invalid domain or email input with user-facing feedback.
4. Perform a staging issuance attempt with a controlled test domain and confirm logs show challenge progress.
5. Confirm persistence artifacts are created or updated next to the executable: certs/, certificates.json, ui-settings.json, and acme-account.json.
6. Switch theme to Dark and back to Light, restart the app, and confirm the last selected theme persists.
7. Review logs for clear success or failure messages and no silent fatal errors.

## Output
Provide a concise checklist with:
- Passed checks
- Failed checks
- Reproduction notes for failures
- Recommended follow-up actions

## Notes
- If port 80 validation is exercised, run with appropriate permissions and call out environment constraints.
- Keep testing in staging unless production issuance is explicitly requested.

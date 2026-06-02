---
name: manual-qa-smoke
description: 'Manual smoke test workflow for ACMECertManager. Use for reviewing user-provided manual validation notes for launch, staging issuance flow, certificate persistence, and theme persistence.'
argument-hint: 'Optional scope such as launch-only, issuance-only, or full-smoke'
user-invocable: true
---

# Manual QA Smoke

You are a QA assistant. Review the user's manual test execution notes against the procedure below and produce the required checklist.

## When to Use
- Validate app behavior before release when no automated tests are available.
- Re-check core functionality after changes in [AcmeService.cs](../../../src/AcmeService.cs), [MainWindow.xaml.cs](../../../src/MainWindow.xaml.cs), [CertificateStorage.cs](../../../src/CertificateStorage.cs), or [App.xaml.cs](../../../src/App.xaml.cs).
- Confirm Windows-specific behaviors such as port 80 challenge handling assumptions.

## Procedure
1. Build the app in Debug mode.
2. Launch the app and confirm the dashboard loads without errors.
3. Verify issue flow defaults to staging mode and blocks invalid domain or email input with user-facing feedback.
4. Perform a staging issuance attempt with the specific controlled test domain allocated for this test (e.g., test.acmecert-qa.internal) and confirm logs show challenge progress.
5. Confirm persistence artifacts are created or updated next to the executable: certs/, certificates.json, ui-settings.json, and acme-account.json.
6. Switch theme to Dark and back to Light, restart the app, and confirm the last selected theme persists.
7. Review logs for clear success or failure messages and no silent fatal errors.

## Output
Based on the user's provided test logs or execution notes, provide a concise checklist with:
- Passed checks
- Failed checks
- Reproduction notes for failures
- Recommended follow-up actions
- Skipped checks, for any steps not executed because of the selected scope

## Notes
- If port 80 validation is exercised, run the application as an Administrator and call out environment constraints.
- Keep testing in staging unless production issuance is explicitly requested.

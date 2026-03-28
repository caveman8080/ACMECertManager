---
description: "Use when editing WPF UI files, XAML layout, styles, theme resources, bindings, or MainWindow event handlers. Covers DynamicResource usage, naming, and user-facing feedback patterns."
name: "WPF UI Guidelines"
applyTo: src/**/*.xaml, src/**/*Window.xaml.cs, src/App.xaml.cs
---
# WPF UI Guidelines

- Keep theme-aware visuals in shared resources and prefer DynamicResource for colors and brushes used by controls.
- Reuse existing resource keys when possible (WindowBackgroundBrush, SurfaceBrush, PrimaryTextBrush, SecondaryTextBrush, SuccessBrush, WarningBrush, BorderBrush, LogBackgroundBrush, LogTextBrush).
- Avoid introducing one-off hardcoded colors in page-level controls unless there is a clear product reason.
- Keep UI event handlers small and user focused. Log progress to the logs panel and show MessageBox for blocking failures.
- Preserve existing naming and control wiring patterns, including x:Name identifiers used by code-behind.
- For new user flows, keep visual style consistent with the current tab-based layout and friendly status messaging tone.


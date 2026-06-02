---
description: "Use when editing WPF UI files, XAML layout, styles, theme resources, bindings, or MainWindow event handlers. Covers DynamicResource usage, naming, and user-facing feedback patterns."
name: "WPF UI Guidelines"
applyTo: src/**/*.xaml, src/**/*Window.xaml.cs, src/App.xaml.cs
---
# WPF UI Guidelines

- Keep theme-aware visuals in shared resources and prefer DynamicResource for colors and brushes used by controls.
- Reuse existing resource keys when possible (WindowBackgroundBrush, SurfaceBrush, PrimaryTextBrush, SecondaryTextBrush, SuccessBrush, WarningBrush, BorderBrush, LogBackgroundBrush, LogTextBrush); if a required semantic color is not already defined, add a new DynamicResource key in the shared resource dictionary using the [Usage]Brush naming convention.
- Avoid introducing one-off hardcoded colors in page-level controls unless explicitly requested by the user.
- Keep UI event handlers under 20 lines. Extract business logic into separate methods or services so event handlers only manage UI state and component wiring. Log progress to the logs panel using the standard project logging class, and show MessageBox for blocking failures only.
- For non-blocking or transient errors, write a warning to the logs panel instead of showing a MessageBox.
- Preserve existing naming and control wiring patterns, including x:Name identifiers used by code-behind.
- For new user flows, keep visual style consistent with the current tab-based layout and friendly status messaging tone.


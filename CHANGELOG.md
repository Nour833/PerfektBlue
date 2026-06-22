# Changelog

## 2.1.0 — 2026-06-22

- Added a polished interactive main menu when `perfektblue` runs without a command.
- Added persistent target context, safety-policy status, and session counts.
- Added navigable target, assessment, diagnostics, reports, library, settings, and CAN views.
- Added contextual help, shortcuts, breadcrumbs, progress states, and back navigation.
- Preserved all noninteractive commands and stable JSON output for automation.

## 2.0.0 — 2026-06-22

- Replaced the proof-of-concept script with an installable, typed Python package.
- Replaced PyBluez and `hciconfig` parsing with BlueZ D-Bus discovery.
- Added adaptive profile matching, module planning, evidence, verdicts, and reports.
- Added deterministic vulnerable, patched, and unknown Bluetooth simulators.
- Removed generic overflow, reverse-shell, fixed-port, fixed-offset, and architecture assumptions.
- Moved CAN support into the optional `perfektblue-can` package.
- Added automated tests, wheel builds, Debian builds, SBOM generation, and tagged releases.

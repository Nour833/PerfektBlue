# Architecture

PerfektBlue separates discovery, identification, planning, execution, evidence, and reporting.

```text
BlueZ D-Bus
    │
    ▼
Device evidence ──► profile matcher ──► ranked target profiles
                                         │
                                         ▼
Module registry ──► compatibility + risk planner
                                         │
                                         ▼
                               bounded module execution
                                         │
                                         ▼
                         evidence + findings + verdict
                                         │
                                         ▼
                         SQLite index + JSON/HTML report
```

`BluetoothBackend` isolates live BlueZ access from deterministic simulation. `TargetProfile`
contains matching rules and compatible module identifiers. `AssessmentModule` declares service,
profile, confidence, and risk prerequisites. `AssessmentEngine` selects only compatible modules
and records why every module was selected or skipped.

External modules can register through the `perfektblue.modules` Python entry-point group.

CAN does not participate in the core workflow. The separate `perfektblue-can` distribution can
be installed when passive CAN capture analysis is required.


<div align="center">
  <img src="logo.png" alt="PerfektBlue Bluetooth automotive security logo" width="220">
  <h1>PerfektBlue</h1>
  <p><strong>Bluetooth-first adaptive security assessment framework</strong></p>
</div>

PerfektBlue discovers Bluetooth targets, records their exposed services and security state,
matches them against versioned target profiles, builds a compatible assessment plan, and
produces evidence-backed exploitability reports.

The project no longer contains the original generic RFCOMM overflow proof of concept. A fixed
port, packet, offset, architecture, or payload cannot correctly assess arbitrary Bluetooth
products. PerfektBlue 2 uses target profiles and tested modules, and it refuses to guess when
evidence is insufficient.

## What works

- BlueZ D-Bus adapter enumeration and Classic/BLE discovery.
- Collection of device names, class, appearance, RSSI, UUIDs, manufacturer data, and link state.
- Explainable target-profile scoring with contradictions and confidence.
- Adaptive module planning based on target evidence, service requirements, risk, and policy.
- Precise injection verdicts: `confirmed-injectable`, `blocked`, `no-known-path`,
  `inconclusive`, and `unsupported`.
- SQLite session history with immutable JSON artifacts.
- JSON, terminal, and standalone HTML reports.
- Deterministic vulnerable, patched, and unknown simulators for CI and module development.
- Optional CAN analysis in the separate `perfektblue-can` package.
- Automated wheel and Debian-package builds.

PerfektBlue does not call an untested target “immune.” A blocked result applies only to the
known path that was actually tested.

## Install

Python 3.11 or newer and Linux with BlueZ are required.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
perfektblue doctor
```

Release tags publish a `.deb` on GitHub. Install it with:

```bash
sudo apt install ./perfektblue_2.1.0-1_all.deb
```

The application itself does not require global root execution. BlueZ permissions are reported
by `perfektblue doctor`.

## Quick start

Open the interactive Bluetooth intelligence console:

```bash
perfektblue
```

The menu keeps the selected target, assessment context, safety policy, and recent sessions
visible while you navigate discovery, fingerprinting, planning, assessment, and reports.

List adapters and discover nearby targets:

```bash
perfektblue adapters
perfektblue discover
perfektblue fingerprint AA:BB:CC:DD:EE:FF
perfektblue plan AA:BB:CC:DD:EE:FF
perfektblue assess AA:BB:CC:DD:EE:FF
```

Machine-readable output is available on every primary command:

```bash
perfektblue --json discover
```

Run the complete deterministic simulator:

```bash
perfektblue --backend simulated --scenario vulnerable discover
perfektblue --backend simulated --scenario vulnerable fingerprint 02:00:00:00:20:01
perfektblue --backend simulated --scenario vulnerable \
  --risk lab-active assess --authorized 02:00:00:00:20:01
```

Use `--scenario patched` to verify the blocked verdict and `--scenario unknown` to verify that
unsupported targets never receive an active module.

## Risk policy

PerfektBlue modules declare one of three levels:

- `passive`: inventory and evidence collection.
- `active-safe`: bounded protocol interaction without payload execution.
- `lab-active`: target-specific verification that requires written authorization.

The default is `passive`. Lab-active execution requires both
`--risk lab-active` and `--authorized`. Bundled active verification is restricted to the
in-memory simulator; real hardware requires an independently tested profile and module.

## Configuration

Precedence is:

```text
CLI → PERFEKTBLUE_* environment → user TOML → system TOML → defaults
```

User configuration is read from `~/.config/perfektblue/config.toml`:

```toml
[perfektblue]
backend = "bluez"
scan_seconds = 15
settle_seconds = 2
command_timeout = 30
max_retries = 2
minimum_auto_match = 80
minimum_suggested_match = 50
risk_policy = "passive"
redact_identifiers = false
```

Sessions are stored under `~/.local/share/perfektblue/`; caches use
`~/.cache/perfektblue/`.

## Main commands

```text
menu
wizard
doctor
adapters
discover
inspect TARGET
fingerprint TARGET
plan TARGET
assess [TARGET]
profiles list|match|validate
modules list|describe|validate
sessions list|show|export
report SESSION
migrate legacy-can PATH
can
```

See [architecture](docs/architecture.md), [module authoring](docs/module-authoring.md),
[safety policy](docs/safety.md), and [releasing](docs/releasing.md).

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy src/perfektblue
pytest
python scripts/build_deb.py
```

The Debian package is generated into `dist/`. No Debian staging tree or duplicated executable
is tracked in the repository.

## Legal and safety

Use PerfektBlue only on systems you own or have explicit written authorization to assess.
Bluetooth and automotive systems can be safety-critical. Use controlled benches, simulators,
and isolated labs. See [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

PerfektBlue is licensed under the [MIT License](LICENSE).

# Ground-System Security Suite

[English](README.md) | [简体中文](README.zh-CN.md)

This suite tests the ground-control boundary of a live NOS3/cFS mission: command authorization and release, command dictionaries, audit attribution, ground configuration, command/telemetry availability, display integrity, privilege boundaries, and credential reuse. Every case has an executable YAML definition in `scenarios/` and a corresponding runner in `benchmark_engine.ground_system`.

## Implemented cases

| ID | Attack exercised |
| --- | --- |
| GS-001 | Dangerous telecommand independently authorized and scored per command |
| GS-002 | COSMOS/OpenC3 command-dictionary semantic pollution |
| GS-003 | Command success without an attributable audit trail |
| GS-004 | Ground configuration pollution |
| GS-005 | Ground command and telemetry service denial of service |
| GS-006 | Telemetry display and monitoring deception |
| GS-007 | Partial-privilege command escalation |
| GS-008 | Credential-reuse command send |

## Run

Validate all registered cases without executing live commands:

```bash
python3 -m benchmark_engine.ground_system.gs_run_all --dry-run
```

Run the complete batch in an isolated NOS3/COSMOS environment:

```bash
python3 -m benchmark_engine.ground_system.gs_run_all \
  --output-dir artifacts/runs/ground_system
```

Use `--case GS-003` (repeatable) to narrow the batch. The runner creates a directory for each selected case and writes `summary.json`; it continues after case failures so the final report represents the whole selection. GS-004 and GS-005 are intentionally invoked with their required live-impact acknowledgement flags by `gs_run_all`.

GS-001 can also be exercised directly with `benchmark_engine.ground_system.live_runner`; use `--case` to select individual dangerous-TC subcases. See `../../docs/ground_system.md` for the concise operational entry point.

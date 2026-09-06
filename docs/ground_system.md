# Ground-System Security Suite

This suite covers threats at the ground-control boundary: command release,
COSMOS dictionaries, audit attribution, configuration, service availability,
monitoring, authorization, and credential reuse.

- `scenarios/` contains the executable GS scenario definitions.
- `benchmark_engine.ground_system` contains the live runners and per-case
  implementations.

Run the generic scenario index:

```bash
python3 -m benchmark_engine.cli.benchmark --domain ground_system --dry-run
```

Run the live ground-system dispatcher:

```bash
python3 -m benchmark_engine.ground_system.live_runner --dry-run
```

Run every registered Ground-system case sequentially:

```bash
python3 -m benchmark_engine.ground_system.gs_run_all
```

The batch writes one artifact directory per GS case and a batch `summary.json`.
It continues after failures.

# cFS/NOS3 Security Benchmark

This project builds a repeatable security benchmark for cFS running in the
NOS3 simulation environment.

The benchmark keeps one common description model for every attack:

```text
attack entry -> affected component -> CPS type -> security consequence -> recovery strategy -> NOS3/cFS injection method
```

## Attack Domains

The full benchmark is organized into four implementation batches:

1. RF-link security
2. Space platform security
3. Ground systems security
4. Mission operations and supply-chain security

This first version implements the RF-link security batch.

## RF-link Security Batch

RF-link scenarios model attacks on command and telemetry links between a ground
system and spacecraft communication interfaces. In NOS3/cFS, these attacks are
represented by a UDP attack proxy. For formal benchmark runs, the proxy can be
inserted transparently with iptables, so COSMOS/YAMCS can keep sending to the
original cFS/NOS3 endpoint.

Implemented attack effects:

- packet drop
- packet delay
- packet replay
- packet bit flip
- packet flood
- packet fabrication
- packet reordering
- packet eavesdropping/logging

## Quick Start

Run all RF-link scenarios in dry-run mode:

```powershell
python -m cfs_security_benchmark.runner.run_benchmark --domain rf_link --dry-run
```

Run all RF-link scenarios in dry-run mode:

```powershell
python -m cfs_security_benchmark.runner.run_benchmark --domain rf_link --dry-run
```

Preview a transparent RF-link run without changing iptables:

```bash
python3 -m cfs_security_benchmark.runner.run_rf_link \
  --scenario scenarios/rf_link/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 \
  --listen-port 19000 \
  --transparent \
  --chain PREROUTING \
  --dry-run
```

Run a transparent RF-link benchmark in the NOS3 VM:

```bash
sudo python3 -m cfs_security_benchmark.runner.run_rf_link \
  --scenario scenarios/rf_link/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 \
  --listen-port 19000 \
  --transparent \
  --chain PREROUTING \
  --duration 60 \
  --log reports/rf_link_eavesdrop_nos3.jsonl
```

In transparent mode, COSMOS/YAMCS still sends to the original target. The runner
temporarily adds an iptables redirect rule, starts the proxy, forwards traffic
to the real target, and removes the rule when the run ends.

Use `--chain PREROUTING` when COSMOS/YAMCS is inside a Docker container and the
packets cross the NOS3 VM host bridge. Use `--chain OUTPUT` when the sender is a
local process running directly on the same Linux host as the proxy.

The manual proxy entry point is still useful for local tests:

```powershell
python -m cfs_security_benchmark.attacks.rf_link_proxy `
  --scenario scenarios/rf_link/link_delay.yaml `
  --listen 0.0.0.0:5000 `
  --target 127.0.0.1:5010
```

## Scenario Fields

Each scenario stores both research meaning and executable parameters:

- `attack_entry`
- `affected_component`
- `cps_type`
- `security_consequence`
- `recovery_strategy`
- `injection_method`
- `attack`
- `metrics`
- `pass_criteria`

This lets the benchmark remain readable as a research artifact while still
being executable.

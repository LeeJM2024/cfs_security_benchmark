# cFS/NOS3 Security Benchmark

[English](README.md) | [简体中文](README.zh-CN.md)

An executable security benchmark for [NASA cFS](https://cfs.gsfc.nasa.gov/) in the NOS3 simulation environment. The repository measures whether an attack reaches a **real NOS3/cFS target effect** and records the evidence needed to reproduce, assess, and recover from that run. It is not a collection of synthetic victim applications.

## What is implemented

| Suite | Current coverage | Primary execution surface |
| --- | --- | --- |
| RF link | 8 attack scenarios, each evaluated as uplink and downlink | UDP proxy, transparent interception, packet capture |
| Space platform | SP001–SP008 real cFS/NOS3 injection packages | cFS applications, configuration mutations, COSMOS/OpenC3 verifiers |
| Ground system | GS001–GS008 executable scenarios | COSMOS/OpenC3 commands, dictionaries, configuration, audit and service paths |
| Supply chain | 5 SC-APP architectures × 6 selectable payloads; 5 SC-ART release paths | Vendor-style cFS apps, signed artifact releases, transactional staging and native ingress audit |

The common research-to-execution model is:

```text
attack entry → affected component → CPS type → security consequence
             → recovery strategy → NOS3/cFS injection method → evidence
```

## Repository map

- `benchmark_engine/` — Python runners, lifecycle orchestration, scoring, report generation and NOS3/COSMOS helpers.
- `security_suites/rf_link/` — RF scenarios, threat models and live-run scripts.
- `security_suites/space_platform/injections/` — SP001–SP008 installation, verification and cleanup packages.
- `security_suites/ground_system/` — GS001–GS008 scenario specifications and runners.
- `security_suites/supply_chain/` — SC-APP components, SC-ART manifests, installers, recovery helper and verifiers.
- `docs/` — detailed operational notes for each domain.
- `artifacts/` — generated reports and run evidence; not source material.

## Evidence and verdicts

`PASS` always means the requested attack reached its intended real target effect. A rejected operation, parser refusal, or intact native state is evidence of a defense; it is not silently counted as an attack success. Individual runners also retain raw command results, telemetry/event observations, configuration or file evidence, and recovery results in their output directories.

Live cases can change flight-software state, generated configuration, tables, COSMOS dictionaries, files, service load, or network traffic. Run them only in an isolated, disposable NOS3 environment. Start with `--dry-run`, inspect the selected profile, and complete the documented cleanup/recovery checkpoint before moving to another phase.

## Safe discovery

List the executable supply-chain matrix without running a payload:

```bash
python3 -m benchmark_engine.supply_chain
```

Validate the scenario-index paths without sending live commands:

```bash
python3 -m benchmark_engine.cli.benchmark --domain rf_link --dry-run
python3 -m benchmark_engine.cli.benchmark --domain ground_system --dry-run
python3 -m benchmark_engine.ground_system.gs_run_all --dry-run
python3 -m benchmark_engine.space_platform.verify_all --dry-run
```

## Domain entry points

### RF link

Run all eight radio-link benchmarks in both directions after first validating the environment:

```bash
python3 -m benchmark_engine.rf_link.live_runner --all --link radio --direction both
```

See [RF-link suite](security_suites/rf_link/README.md) for the scenario matrix, transparent-mode behavior, and recovery of interrupted iptables rules.

### Space platform

The normal **clean** phase verifies SP001–SP004 and SP006–SP008. SP005 is deliberately separate because it changes source/simulator configuration and requires a rebuild/restart checkpoint both before attack verification and after restore.

```bash
# Install registered SP packages, then build and launch NOS3 by its normal flow.
python3 -m benchmark_engine.lifecycle.prep --nos3-root /home/leejm/nos3 --domains space_platform
cd /home/leejm/nos3 && make config && make fsw && make launch

# Run the clean phase; hazardous SP001 profiles require explicit confirmation.
python3 -m benchmark_engine.space_platform.verify_all --phase clean

# Remove installed packages after verification.
python3 -m benchmark_engine.lifecycle.cleanup --nos3-root /home/leejm/nos3 --domains space_platform
```

For SP005, use `--prepare-sp005`, rebuild/restart, run `--phase sp005`, then use `--restore-sp005` and rebuild/restart again. See [Space-platform suite](security_suites/space_platform/README.md).

### Ground system

Run the whole GS001–GS008 batch; it writes one directory per case plus `summary.json` and continues after a case failure:

```bash
python3 -m benchmark_engine.ground_system.gs_run_all
```

GS004 and GS005 require the runner's explicit live-impact acknowledgement; the batch supplies those flags. See [Ground-system suite](security_suites/ground_system/README.md).

### Supply chain

The combined preparation stage installs the vendor apps and stages all declared SC-ART transactions. It intentionally stops before build/relaunch and never restarts CmdTlmServer itself:

```bash
python3 -m benchmark_engine.supply_chain.batch --phase prepare \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_batch
cd /home/leejm/nos3 && make config && make fsw && make stop && make launch
python3 -m benchmark_engine.supply_chain.full_batch --track all \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_full
```

Roll back in the required reverse order, then rebuild/relaunch before recovery verification:

```bash
python3 -m benchmark_engine.supply_chain.batch --phase clean \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_batch
```

See [Supply-chain suite](security_suites/supply_chain/README.md) for profile selection, manual CmdTlmServer reload checkpoints, and dynamic-NOVATEL recovery.

## Prerequisites

Run commands from this repository (or ensure it is on `PYTHONPATH`). Live execution expects a working NOS3 checkout, Docker access to the NOS3/COSMOS/OpenC3 containers, and the project dependencies in `requirements.txt`. Some RF transparent-mode commands additionally require Linux root privileges for iptables.

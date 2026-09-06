# Supply-Chain Security Suite

[English](README.md) | [简体中文](README.zh-CN.md)

This suite measures delivery-chain attacks that enter the real NOS3/cFS integration flow. It owns the carrier, acceptance, dormancy, trigger, coordination, provenance, rollback and recovery evidence; SP and GS implementations provide the native target effects reused by the supply-chain profiles.

## Executable matrix

### SC-APP: supplier application carrier

`sc_vendor_nav` and `sc_vendor_diag` are installed as normal NOS3 components, added to `targets.cmake` and the cFE startup path, then built with the mission. Five architectures have live verification:

| Profile | Components | Trigger | Coordination |
| --- | --- | --- | --- |
| SC-APP-001 | nav | static delay/time | none |
| SC-APP-002 | nav | real NOVATEL telemetry | none |
| SC-APP-003 | nav + diag | static delay/time | cFS Software Bus |
| SC-APP-004 | nav + diag | real NOVATEL telemetry | cFS Software Bus |
| SC-APP-005 | nav + diag | real NOVATEL telemetry | POSIX FIFO |

Each architecture exposes six payload choices: `SC-PAYLOAD-EXFIL`, plus native-target adapters for SP001, SP003, SP006, SP007 and SP008. The full application matrix is therefore 30 selectable live cases.

### SC-ART: mission-artifact delivery

| Profile | Delivered artifact | Native target / validation path |
| --- | --- | --- |
| SC-ART-001 | Flight-table release | SP004 table-tampering verifier |
| SC-ART-002 | Component-configuration release | SP005 source → generated → runtime verification |
| SC-ART-003 | COSMOS command dictionary | GS002; manual CmdTlmServer reload checkpoint |
| SC-ART-004 | Ground procedure or route | GS004; manual CmdTlmServer reload checkpoint |
| SC-ART-005 | Revoked, rollback or version-mismatched release | Native NOS3 release-ingress audit |

Release manifests bind identity, content hashes, target operations and a local benchmark signature. Transactions snapshot declared target files and restore them on rollback. SC-ART-005 deliberately does **not** invoke the optional release gate: no native admission hook is itself an attack success.

## Run

List profiles without execution:

```bash
python3 -m benchmark_engine.supply_chain
```

Prepare both tracks, build/relaunch once, then run the full 35-case verification matrix:

```bash
python3 -m benchmark_engine.supply_chain.batch --phase prepare \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_batch
cd /home/leejm/nos3 && make config && make fsw && make stop && make launch
python3 -m benchmark_engine.supply_chain.full_batch --track all \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_full
```

For a single profile, use `python3 -m benchmark_engine.supply_chain --profile-id SC-APP-001` and select a payload with `--payload-id`. SC-ART-003/004 emit a manual reload checkpoint; the operator must reload CmdTlmServer and pass `--operator-reload-confirmed` before staged verification. Clean in reverse transaction order after every campaign:

```bash
python3 -m benchmark_engine.supply_chain.batch --phase clean \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_batch
```

If an earlier dynamic run leaves NOVATEL unavailable, run `nos3_dynamic_recover.py --dry-run` first, then the helper without `--dry-run` inside the NOS3 VM. It restarts only NOS Engine, GPS simulator, FSW and time-driver, never COSMOS/CmdTlmServer.

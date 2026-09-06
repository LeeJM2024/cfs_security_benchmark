# Space-Platform Security Suite

[English](README.md) | [简体中文](README.zh-CN.md)

Eight real NOS3/cFS injection packages live in `injections/`. Each package includes an installer, a verifier and an uninstaller; application-backed cases also include cFS flight-software and COSMOS/OpenC3 dictionary artifacts.

| ID | Attack family |
| --- | --- |
| SP001 | Software Bus command spoofing |
| SP002 | Malformed telecommand injection |
| SP003 | Application lifecycle, crash and restart pressure |
| SP004 | Flight-software table tampering |
| SP005 | Component/source configuration pollution |
| SP006 | Payload and critical-interface abuse |
| SP007 | CPU, bus, event, storage and IPC resource exhaustion |
| SP008 | Subsystem-state and telemetry spoofing |

## Lifecycle

Install the packages, then build and launch NOS3 normally:

```bash
python3 -m benchmark_engine.lifecycle.prep \
  --nos3-root /home/leejm/nos3 --domains space_platform
cd /home/leejm/nos3 && make config && make fsw && make launch
```

The clean phase runs SP001–SP004 and SP006–SP008. Hazardous SP001 profiles are excluded unless explicitly selected and confirmed:

```bash
python3 -m benchmark_engine.space_platform.verify_all --phase clean
python3 -m benchmark_engine.space_platform.verify_all \
  --sp001-risk all --confirm-hazard --phase clean
```

SP005 is intentionally isolated: apply all field-level mutations, rebuild/restart, verify, restore, and rebuild/restart once more.

```bash
python3 -m benchmark_engine.space_platform.verify_all --prepare-sp005
# in NOS3: make config && make fsw && make sim; restart NOS3/cFS/simulators
python3 -m benchmark_engine.space_platform.verify_all --phase sp005
python3 -m benchmark_engine.space_platform.verify_all --restore-sp005
```

After testing, uninstall in reverse package order:

```bash
python3 -m benchmark_engine.lifecycle.cleanup \
  --nos3-root /home/leejm/nos3 --domains space_platform
```

Do not treat a verifier's own log as evidence of success: the verifier scores native telemetry, events, files, tables, configuration, or runtime state at the target. Package-specific procedures are documented in their injection directories.

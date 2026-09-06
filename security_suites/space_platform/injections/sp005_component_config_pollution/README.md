# SP005 — Component Configuration Pollution

[English](README.md) | [简体中文](README.zh-CN.md)

SP005 mutates one field at a time in real NOS3 component or simulator configuration; it does not install a malicious cFS app. `sp005_profiles.json` currently covers ADCS, EPS and 42 configuration values. Each change records the actual original value, SHA-256-backed backup and field-level diff.

Verification requires source configuration, generated/runtime configuration and target observability. Run it as its own phase:

```bash
python3 -m benchmark_engine.space_platform.verify_all --prepare-sp005
# rebuild/restart NOS3, cFS and simulators
python3 -m benchmark_engine.space_platform.verify_all --phase sp005
python3 -m benchmark_engine.space_platform.verify_all --restore-sp005
```

Do not restore between profiles. After restore, rebuild/restart and run restore verification before uninstalling the procedure artifacts.

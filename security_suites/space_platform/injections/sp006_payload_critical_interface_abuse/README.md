# SP006 — Payload and Critical-Interface Abuse

[English](README.md) | [简体中文](README.zh-CN.md)

SP006 is a real cFS injection app that drives critical payload/actuator interfaces through native command paths. Implemented verifier profiles cover interrupted or out-of-order CAM activity, reaction-wheel torque while disabled, and thruster percentage commands while disabled. Target telemetry, events and recovery—not SP006 self-reporting—determine the verdict.

The package supplies FSW, COSMOS/OpenC3 dictionary, installer, verifier and uninstaller. Use `SP006_ONLY` in the verifier environment to select profiles when diagnosing a single interface.

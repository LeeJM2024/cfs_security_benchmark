# SP001 — Software Bus Command Spoof

[English](README.md) | [简体中文](README.zh-CN.md)

SP001 installs a cFS application that publishes unauthorized command messages directly onto the cFE Software Bus. Its targets are native NOS3 components—for example, an injected `GENERIC_ADCS` mode command—and the verifier scores target telemetry, command/event evidence and restored state rather than the spoofer's log.

The package contains the cFS component, COSMOS/OpenC3 dictionary, installer, Ruby verifier, a dedicated reaction-wheel live-link verifier, and uninstaller. `verify_all --phase clean` selects safe profiles by default. Profiles classified as hazardous require `--sp001-risk hazardous|all --confirm-hazard`.

# SP008 — Subsystem State and Telemetry Spoof

[English](README.md) | [简体中文](README.zh-CN.md)

SP008 injects false native-looking subsystem state while the corresponding real subsystem remains in a contradictory state. Current profiles cover EPS power, ADCS mode, reaction wheel, thruster, torquer, mission-manager and GPS/NOVATEL state. The verifier requires both forged telemetry and independent evidence of the real state mismatch, followed by recovery after the spoof stops.

Install, verify and uninstall it through the shared space-platform lifecycle. SC-APP payload selection can reuse its native target effect.

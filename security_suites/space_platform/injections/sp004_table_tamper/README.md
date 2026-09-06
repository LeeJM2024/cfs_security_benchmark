# SP004 — Flight-Software Table Tampering

[English](README.md) | [简体中文](README.zh-CN.md)

SP004 installs a cFS application and malicious but format-valid table artifacts. The verifier drives real table load/validate/activate paths and scores native table telemetry, owner application state, files and events. Coverage includes DS, LC, CF, FM, SBN, SC, SCH and TO table targets.

Use the package installer/uninstaller as part of the space lifecycle. SC-ART-001 reuses this package to test supplier-delivered flight-table releases.

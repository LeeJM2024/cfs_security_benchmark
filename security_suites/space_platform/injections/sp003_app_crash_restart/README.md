# SP003 — Application Lifecycle and Restart Pressure

[English](README.md) | [简体中文](README.zh-CN.md)

SP003 is a benchmark-owned cFS runtime-pressure application. Its profiles exercise bounded CPU pressure, EVS/syslog bursts, application exit, restart/delete/reload requests and controlled crash-loop behavior against cFE Executive Services.

Success requires cFS/ES evidence of the requested runtime effect; an ES rejection is recorded as a defense. In particular, the scheduler-starvation profile passes only when SCH telemetry shows scheduling impact, not merely because the payload busy loop executed. The package includes its component, dictionary, installer, verifier and uninstaller.

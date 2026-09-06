# SP007 — Resource Exhaustion

[English](README.md) | [简体中文](README.zh-CN.md)

SP007 applies bounded resource pressure through a cFS application. Its current profiles exercise CPU busy-loop child tasks, Software Bus telemetry flood, EVS event storm, `/cf` storage fill, and held Software Bus pipes/OSAL queues. The verifier separates observed attack success, protected outcomes, observation limits and cleanup recovery.

All pressure profiles are bounded and include cleanup logic, but they still affect a live mission simulation. Run them only after recovery has been tested and use the package installer/uninstaller via the shared lifecycle.

# SP001 — 软件总线指令欺骗

[English](README.md) | [简体中文](README.zh-CN.md)

SP001 安装一个 cFS 应用，直接向 cFE 软件总线发布未经授权的指令消息。其目标是真实 NOS3 组件（例如注入 `GENERIC_ADCS` 模式指令）；验证器依据目标遥测、指令/事件证据和恢复状态评分，而不是欺骗程序日志。

该包包含 cFS 组件、COSMOS/OpenC3 字典、安装器、Ruby 验证器、专用反作用飞轮实际链路验证器和卸载器。`verify_all --phase clean` 默认选择安全配置；被归类为危险的配置需要 `--sp001-risk hazardous|all --confirm-hazard`。

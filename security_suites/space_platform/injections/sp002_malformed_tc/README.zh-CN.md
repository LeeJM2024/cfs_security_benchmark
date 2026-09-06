# SP002 — 畸形遥控注入

[English](README.md) | [简体中文](README.zh-CN.md)

SP002 向真实 cFS/NOS3 指令接口发送刻意构造的畸形 CCSDS 遥控，并评估解析器、指令计数器、事件和目标状态。`sp002_run_live.py` 是包入口：它将原始数据包发送器和 Ruby 验证器复制到操作员容器，发现所需返回路径，并支持选定配置 ID 及安全/危险模式。

通过 `install_into_nos3.py` 和 `uninstall_from_nos3.py` 安装与移除该包；完整活动使用共享空间平台生命周期。运行器中的危险模式需要明确确认。

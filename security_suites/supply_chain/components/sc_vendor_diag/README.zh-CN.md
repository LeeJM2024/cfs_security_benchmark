# sc_vendor_diag

[English](README.md) | [简体中文](README.zh-CN.md)

用于串谋 SC-APP 配置的第二个供应商风格诊断 cFS 应用。它发布无害状态遥测，并接收来自 `sc_vendor_nav` 的协同信号：SC-APP-003/004 使用自定义 cFS 软件总线消息，SC-APP-005 在 amd64-posix 上使用 POSIX FIFO 信号。单组件配置不需要它。

它的飞行软件和 COSMOS/OpenC3 字典工件会由套件安装器随 `sc_vendor_nav` 一同安装。

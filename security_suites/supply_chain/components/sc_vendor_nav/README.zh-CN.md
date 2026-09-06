# sc_vendor_nav

[English](README.md) | [简体中文](README.zh-CN.md)

SC-APP 使用的主要供应商风格导航/健康状态 cFS 应用。它发布无害诊断状态遥测，支持静态和 NOVATEL 驱动的触发路径，并作为 SC-APP-001/002 的单组件载体。在串谋配置中，它发起软件总线或 FIFO 协同信号，并暴露 6 种可选择的供应链载荷适配器。

其 FSW 源码位于 `fsw/cfs/`；`gsw/cosmos/cmd_tlm/SC_VENDOR_NAV.txt` 提供 COSMOS/OpenC3 指令和遥测字典。应通过套件安装器安装，避免零散复制文件。

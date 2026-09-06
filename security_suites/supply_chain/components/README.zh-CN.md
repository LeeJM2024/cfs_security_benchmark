# SC-APP 组件

[English](README.md) | [简体中文](README.zh-CN.md)

这些是真实 cFS 应用，而不是仅用于基准测试的受害对象。安装器会将它们复制到 NOS3 组件树，在任务目标/启动配置中注册，并由正常 NOS3 构建生成可运行模块和 COSMOS 字典。

`sc_vendor_nav` 是主要载体：它观测静态时间或 NOVATEL 遥测，维持无害诊断接口，并在触发后驱动选定载荷。`sc_vendor_diag` 是串谋配置使用的第二载体；它通过软件总线消息或 POSIX FIFO 协同。验证器必须观测原生 NOS3 状态、TO_LAB/radio-sim 输出、COSMOS 证据或真实 cFS 状态，而非仅凭恶意遥测自报。

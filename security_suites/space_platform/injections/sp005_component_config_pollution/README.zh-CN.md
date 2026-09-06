# SP005 — 组件配置污染

[English](README.md) | [简体中文](README.zh-CN.md)

SP005 每次修改一个真实 NOS3 组件或模拟器配置字段；它不安装恶意 cFS 应用。`sp005_profiles.json` 当前覆盖 ADCS、EPS 和 42 配置值。每个修改都会记录实际原始值、带 SHA-256 的备份和字段级 diff。

验证要求源配置、生成/运行时配置及目标可观测性。它必须作为独立阶段运行：

```bash
python3 -m benchmark_engine.space_platform.verify_all --prepare-sp005
# 重建/重启 NOS3、cFS 和模拟器
python3 -m benchmark_engine.space_platform.verify_all --phase sp005
python3 -m benchmark_engine.space_platform.verify_all --restore-sp005
```

不要在配置之间恢复。恢复后，应重建/重启并执行恢复验证，再卸载流程工件。

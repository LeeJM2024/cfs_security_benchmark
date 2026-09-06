# 地面系统安全套件

[English](README.md) | [简体中文](README.zh-CN.md)

本套件测试实际 NOS3/cFS 任务的地面控制边界：指令授权与发布、指令字典、审计归因、地面配置、指令/遥测可用性、显示完整性、权限边界和凭据复用。每个用例在 `scenarios/` 中都有可执行 YAML 定义，并在 `benchmark_engine.ground_system` 中拥有对应运行器。

## 已实现用例

| ID | 测试的攻击 |
| --- | --- |
| GS-001 | 独立授权危险遥控，并逐条评分 |
| GS-002 | COSMOS/OpenC3 指令字典语义污染 |
| GS-003 | 指令成功但没有可归因审计轨迹 |
| GS-004 | 地面配置污染 |
| GS-005 | 地面指令与遥测服务拒绝服务 |
| GS-006 | 遥测显示与监测欺骗 |
| GS-007 | 部分权限的指令权限提升 |
| GS-008 | 凭据复用发送指令 |

## 运行

验证所有已注册用例而不执行实际指令：

```bash
python3 -m benchmark_engine.ground_system.gs_run_all --dry-run
```

在隔离的 NOS3/COSMOS 环境中运行完整批次：

```bash
python3 -m benchmark_engine.ground_system.gs_run_all \
  --output-dir artifacts/runs/ground_system
```

使用可重复的 `--case GS-003` 缩小批次范围。运行器会为每个选定用例创建目录并写入 `summary.json`；即使某个用例失败也会继续，因此最终报告覆盖全部选择。`gs_run_all` 会为 GS-004 和 GS-005 自动提供所需的实际影响确认标志。

GS-001 也可直接通过 `benchmark_engine.ground_system.live_runner` 执行；使用 `--case` 可选择单个危险遥控子用例。简要操作入口见 `../../docs/ground_system.md`。

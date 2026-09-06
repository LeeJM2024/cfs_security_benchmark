# cFS/NOS3 安全基准测试

[English](README.md) | [简体中文](README.zh-CN.md)

这是一个面向 [NASA cFS](https://cfs.gsfc.nasa.gov/) 与 NOS3 仿真环境的可执行安全基准测试。仓库评估攻击是否到达**真实 NOS3/cFS 目标效果**，并保留可复现、判定和恢复该次运行所需的证据；它并非一组人为构造的受害应用。

## 已实现内容

| 套件 | 当前覆盖范围 | 主要执行面 |
| --- | --- | --- |
| 射频链路 | 8 个攻击场景，分别按上行与下行评估 | UDP 代理、透明拦截、抓包 |
| 空间平台 | SP001–SP008 真实 cFS/NOS3 注入包 | cFS 应用、配置修改、COSMOS/OpenC3 验证器 |
| 地面系统 | GS001–GS008 可执行场景 | COSMOS/OpenC3 指令、字典、配置、审计和服务路径 |
| 供应链 | 5 种 SC-APP 架构 × 6 种可选载荷；5 条 SC-ART 发布路径 | 供应商风格 cFS 应用、签名工件发布、事务化暂存与原生入口审计 |

统一的“研究含义到执行”模型为：

```text
攻击入口 → 受影响组件 → CPS 类型 → 安全后果
         → 恢复策略 → NOS3/cFS 注入方法 → 证据
```

## 仓库结构

- `benchmark_engine/`：Python 运行器、生命周期编排、评分、报告及 NOS3/COSMOS 辅助代码。
- `security_suites/rf_link/`：射频场景、威胁模型和实际运行脚本。
- `security_suites/space_platform/injections/`：SP001–SP008 的安装、验证和清理包。
- `security_suites/ground_system/`：GS001–GS008 场景规格和运行器。
- `security_suites/supply_chain/`：SC-APP 组件、SC-ART 清单、安装器、恢复辅助工具和验证器。
- `docs/`：按领域组织的详细操作说明。
- `artifacts/`：生成的报告和运行证据，不是源文件。

## 证据与判定

`PASS` 始终表示请求的攻击已经达成预期的真实目标效果。操作被拒绝、解析器拒收或原生状态保持完好，均是防御证据，不会被悄然计为攻击成功。各运行器还会在输出目录中保留原始指令结果、遥测/事件观测、配置或文件证据以及恢复结果。

实际用例可能修改飞行软件状态、生成配置、表、COSMOS 字典、文件、服务负载或网络流量。请只在隔离且可丢弃的 NOS3 环境中执行。先使用 `--dry-run`，检查选定配置，并在进入下一阶段前完成文档规定的清理/恢复检查点。

## 安全发现

仅列出可执行供应链矩阵，不执行载荷：

```bash
python3 -m benchmark_engine.supply_chain
```

验证场景索引路径，不发送实际指令：

```bash
python3 -m benchmark_engine.cli.benchmark --domain rf_link --dry-run
python3 -m benchmark_engine.cli.benchmark --domain ground_system --dry-run
python3 -m benchmark_engine.ground_system.gs_run_all --dry-run
python3 -m benchmark_engine.space_platform.verify_all --dry-run
```

## 各领域入口

### 射频链路

先验证环境后，沿两个方向运行全部八项无线电链路基准测试：

```bash
python3 -m benchmark_engine.rf_link.live_runner --all --link radio --direction both
```

场景矩阵、透明模式行为及 iptables 异常中断后的恢复方法，请参见[射频链路套件](security_suites/rf_link/README.zh-CN.md)。

### 空间平台

常规的 **clean** 阶段会验证 SP001–SP004 和 SP006–SP008。SP005 会更改源/模拟器配置，因此刻意独立：攻击验证前及恢复后均必须经过重建/重启检查点。

```bash
# 安装已注册 SP 包，然后按正常流程构建并启动 NOS3。
python3 -m benchmark_engine.lifecycle.prep --nos3-root /home/leejm/nos3 --domains space_platform
cd /home/leejm/nos3 && make config && make fsw && make launch

# 运行 clean 阶段；危险 SP001 配置须明确确认。
python3 -m benchmark_engine.space_platform.verify_all --phase clean

# 验证后移除已安装包。
python3 -m benchmark_engine.lifecycle.cleanup --nos3-root /home/leejm/nos3 --domains space_platform
```

SP005 应依次使用 `--prepare-sp005`、重建/重启、`--phase sp005`、`--restore-sp005`，再重建/重启。详见[空间平台套件](security_suites/space_platform/README.zh-CN.md)。

### 地面系统

运行 GS001–GS008 全批次；它会为每个用例写入一个目录和 `summary.json`，并会在某个用例失败后继续：

```bash
python3 -m benchmark_engine.ground_system.gs_run_all
```

GS004 和 GS005 需要运行器明确确认实际影响；批量运行器会提供这些标志。详见[地面系统套件](security_suites/ground_system/README.zh-CN.md)。

### 供应链

联合准备阶段会安装供应商应用并暂存全部已声明 SC-ART 事务。它会在构建/重新启动前有意停下，且绝不会自行重启 CmdTlmServer：

```bash
python3 -m benchmark_engine.supply_chain.batch --phase prepare \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_batch
cd /home/leejm/nos3 && make config && make fsw && make stop && make launch
python3 -m benchmark_engine.supply_chain.full_batch --track all \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_full
```

必须按反向顺序回滚，然后重建/重新启动后再验证恢复：

```bash
python3 -m benchmark_engine.supply_chain.batch --phase clean \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_batch
```

配置选择、CmdTlmServer 手动重载检查点及动态 NOVATEL 恢复方法，详见[供应链套件](security_suites/supply_chain/README.zh-CN.md)。

## 前置条件

请从此仓库运行命令（或确保其位于 `PYTHONPATH`）。实际执行需要可用的 NOS3 检出、能访问 NOS3/COSMOS/OpenC3 容器的 Docker 环境，以及 `requirements.txt` 声明的依赖。部分射频透明模式命令还需要 Linux root 权限来操作 iptables。

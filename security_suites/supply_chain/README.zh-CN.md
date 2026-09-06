# 供应链安全套件

[English](README.md) | [简体中文](README.zh-CN.md)

本套件度量进入真实 NOS3/cFS 集成流程的交付链攻击。它负责载体、接受、潜伏、触发、协同、溯源、回滚和恢复证据；SP 与 GS 实现提供供应链配置复用的原生目标效果。

## 可执行矩阵

### SC-APP：供应商应用载体

`sc_vendor_nav` 和 `sc_vendor_diag` 会作为普通 NOS3 组件安装，加入 `targets.cmake` 与 cFE 启动路径，再随任务一同构建。以下五种架构已具备实际验证：

| 配置 | 组件 | 触发器 | 协同方式 |
| --- | --- | --- | --- |
| SC-APP-001 | nav | 静态延迟/时间 | 无 |
| SC-APP-002 | nav | 真实 NOVATEL 遥测 | 无 |
| SC-APP-003 | nav + diag | 静态延迟/时间 | cFS 软件总线 |
| SC-APP-004 | nav + diag | 真实 NOVATEL 遥测 | cFS 软件总线 |
| SC-APP-005 | nav + diag | 真实 NOVATEL 遥测 | POSIX FIFO |

每种架构提供 6 种载荷选择：`SC-PAYLOAD-EXFIL`，以及面向 SP001、SP003、SP006、SP007、SP008 原生目标的适配器。因此完整应用矩阵包含 30 个可选实际用例。

### SC-ART：任务工件交付

| 配置 | 交付工件 | 原生目标/验证路径 |
| --- | --- | --- |
| SC-ART-001 | 飞行表发布 | SP004 表篡改验证器 |
| SC-ART-002 | 组件配置发布 | SP005 源 → 生成 → 运行时验证 |
| SC-ART-003 | COSMOS 指令字典 | GS002；需手动重载 CmdTlmServer |
| SC-ART-004 | 地面流程或路由 | GS004；需手动重载 CmdTlmServer |
| SC-ART-005 | 已撤销、回滚或版本不匹配的发布版本 | 原生 NOS3 发布入口审计 |

发布清单绑定身份、内容哈希、目标操作和本地基准测试签名。事务会快照已声明的目标文件，并在回滚时恢复。SC-ART-005 特意**不**调用可选发布门：缺少原生准入钩子本身就是攻击成功。

## 运行

仅列出配置而不执行：

```bash
python3 -m benchmark_engine.supply_chain
```

准备两条路径、构建/重新启动一次，再运行完整的 35 用例验证矩阵：

```bash
python3 -m benchmark_engine.supply_chain.batch --phase prepare \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_batch
cd /home/leejm/nos3 && make config && make fsw && make stop && make launch
python3 -m benchmark_engine.supply_chain.full_batch --track all \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_full
```

单个配置可使用 `python3 -m benchmark_engine.supply_chain --profile-id SC-APP-001`，并用 `--payload-id` 选择载荷。SC-ART-003/004 会生成手动重载检查点；操作员必须重载 CmdTlmServer，并在分阶段验证前传入 `--operator-reload-confirmed`。每次活动后按反向事务顺序清理：

```bash
python3 -m benchmark_engine.supply_chain.batch --phase clean \
  --nos3-root /home/leejm/nos3 --output-dir artifacts/supply_chain_batch
```

若之前的动态运行使 NOVATEL 不可用，请先在 NOS3 虚拟机中以 `nos3_dynamic_recover.py --dry-run` 预览，再不带 `--dry-run` 运行该辅助工具。它只重启 NOS Engine、GPS 模拟器、FSW 和 time-driver，绝不重启 COSMOS/CmdTlmServer。

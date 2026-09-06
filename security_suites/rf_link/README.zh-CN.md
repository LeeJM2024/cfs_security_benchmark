# 射频链路安全套件

[English](README.md) | [简体中文](README.zh-CN.md)

本套件评估地面系统与 NOS3/cFS 通信接口之间 UDP 指令和遥测路径的攻击。每个基准标识符都会作为 `uplink`（上行）和 `downlink`（下行）用例执行；两个方向共用一个 ID，但保留独立证据。

## 已实现场景

| ID | 场景 |
| --- | --- |
| RF-LINK-001 | 窃听与转发基线 |
| RF-LINK-002 | 概率性丢包 |
| RF-LINK-003 | 数据包延迟 |
| RF-LINK-004 | 已观测数据包重放 |
| RF-LINK-005 | 数据包比特翻转 |
| RF-LINK-006 | 受限数据包洪泛 |
| RF-LINK-007 | 攻击者控制的伪造数据包 |
| RF-LINK-008 | 缓冲数据包重排序 |

`scenarios/` 保存可执行定义；`threat_models/` 定义可信域和加密边界假设；`scripts/run_live_cases.sh` 是实际运行器的 Shell 入口。

## 安全运行

先检查场景而不修改网络规则：

```bash
python3 -m benchmark_engine.rf_link.simulator_runner \
  --scenario security_suites/rf_link/scenarios/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 --listen-port 19000 \
  --transparent --chain PREROUTING --dry-run
```

仅在 NOS3 虚拟机中运行正式无线电链路矩阵：

```bash
python3 -m benchmark_engine.rf_link.live_runner \
  --all --link radio --direction both
```

透明拦截时，发送端仍指向原始 UDP 端点。运行器会安装范围受限的临时重定向、启动代理、将已标记代理流量转发到真实目标、采集证据，并在正常结束时移除规则。发送端位于 Docker 时使用 `PREROUTING`；只有发送端在代理宿主机本地运行时才使用 `OUTPUT`。运行中断后，继续前应检查并移除遗留规则。详细拓扑、手动代理用法以及建议的低风险测试顺序见 `../../docs/rf_link.md`。

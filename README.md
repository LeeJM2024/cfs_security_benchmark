# cFS/NOS3 安全 Benchmark

这个项目用于为 NOS3 仿真环境中的 cFS 构建一套可重复运行的安全 benchmark。

每个攻击场景都保留同一个描述模型：

```text
攻击入口 -> 受影响组件 -> CPS 对应类型 -> 安全后果 -> 恢复策略 -> NOS3/cFS 注入方式
```

## 攻击域划分

完整 benchmark 按四个批次实现：

1. RF-link security
2. Space platform security
3. Ground systems security
4. Mission operations and supply-chain security

当前版本先实现第一批：RF-link security。

## RF-link Security 批次

RF-link 场景用于模拟地面系统与航天器通信接口之间的指令链路和遥测链路攻击。在 NOS3/cFS 中，这类攻击通过 UDP 攻击代理实现。正式运行 benchmark 时，代理可以通过 iptables 透明插入链路，因此 COSMOS/YAMCS 仍然向原始 cFS/NOS3 目标地址发送数据，不需要手动改地面端配置。

当前已经实现的攻击效果包括：

- 数据包窃听与日志记录
- 数据包丢弃
- 数据包延迟
- 数据包重放
- 数据包位翻转
- 数据包洪泛
- 伪造数据包注入
- 数据包乱序

## 快速开始

在 dry-run 模式下预览所有 RF-link 场景：

```bash
python3 -m cfs_security_benchmark.runner.run_benchmark --domain rf_link --dry-run
```

预览一次透明 RF-link 运行，但不真正修改 iptables：

```bash
python3 -m cfs_security_benchmark.runner.run_rf_link \
  --scenario scenarios/rf_link/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 \
  --listen-port 19000 \
  --transparent \
  --chain PREROUTING \
  --dry-run
```

在 NOS3 虚拟机中运行一次透明 RF-link benchmark：

```bash
sudo python3 -m cfs_security_benchmark.runner.run_rf_link \
  --scenario scenarios/rf_link/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 \
  --listen-port 19000 \
  --transparent \
  --chain PREROUTING \
  --duration 60 \
  --log reports/rf_link_eavesdrop_nos3.jsonl
```

透明模式下，COSMOS/YAMCS 仍然向原始目标发送数据。runner 会临时添加 iptables 重定向规则，启动攻击代理，把流量转发到真实目标，并在运行结束后删除规则。

当 COSMOS/YAMCS 位于 Docker 容器中，并且数据包会经过 NOS3 虚拟机宿主机的 bridge 时，使用 `--chain PREROUTING`。当发送方是直接运行在同一台 Linux 主机上的本地进程时，使用 `--chain OUTPUT`。

手动代理入口仍然适合做本地调试，但这种模式要求发送方直接把流量发到代理端口：

```bash
python3 -m cfs_security_benchmark.attacks.rf_link_proxy \
  --scenario scenarios/rf_link/link_delay.yaml \
  --listen 0.0.0.0:5000 \
  --target 127.0.0.1:5010
```

## 场景字段

每个 scenario 同时保存研究语义和可执行参数：

- `attack_entry`
- `affected_component`
- `cps_type`
- `security_consequence`
- `recovery_strategy`
- `injection_method`
- `attack`
- `metrics`
- `pass_criteria`

这样 benchmark 既可以作为论文/实验中的攻击面描述材料阅读，也可以直接被程序执行。

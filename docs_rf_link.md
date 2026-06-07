# RF-link Security 实现说明

## 研究模型

RF-link 批次使用统一的 benchmark 描述模型：

```text
攻击入口 -> 受影响组件 -> CPS 对应类型 -> 安全后果 -> 恢复策略 -> NOS3/cFS 注入方式
```

对于 RF-link security，典型攻击路径可以描述为：

```text
RF-link / UDP 端点
-> COM interface / CI / TO / radio interface
-> Communication
-> 数据泄露、控制拒绝、控制重放、伪造包注入或畸形包解析
-> 重传、认证、新鲜性检查、速率限制、解析器拒绝、safe mode
-> 插入地面系统与 cFS/NOS3 端点之间的 UDP 攻击代理
```

## 已实现场景

| ID | 攻击类型 | 实现效果 |
| --- | --- | --- |
| RF-LINK-001 | 窃听 | 记录数据包，并原样转发 |
| RF-LINK-002 | 丢包 | 按概率丢弃上行数据包 |
| RF-LINK-003 | 延迟 | 延迟上行数据包转发 |
| RF-LINK-004 | 重放 | 对已观察到的上行数据包进行重复发送 |
| RF-LINK-005 | 位翻转 | 修改数据包中的一个 bit |
| RF-LINK-006 | 洪泛 | 向目标端点持续发送随机数据包 |
| RF-LINK-007 | 伪造包 | 发送攻击者指定的 payload |
| RF-LINK-008 | 乱序 | 缓存一小段数据包，并打乱顺序后转发 |

## NOS3/cFS 透明模式

正式 benchmark 不应该要求用户手动修改 COSMOS/YAMCS 配置。因此推荐使用透明模式：

```text
COSMOS/YAMCS
-> 原始目标，例如 198.18.0.17:6010
-> iptables 把匹配的 UDP 数据包重定向到本地代理
-> RF-link 攻击代理
-> 原始目标，例如 198.18.0.17:6010
```

代理向真实目标转发数据包时会使用 Linux socket mark。iptables 规则会忽略这些带 mark 的代理转发包，从而避免数据包再次被重定向回代理，形成转发循环。

预览 iptables 规则，但不真正修改系统：

```bash
python3 -m cfs_security_benchmark.runner.run_rf_link \
  --scenario scenarios/rf_link/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 \
  --listen-port 19000 \
  --transparent \
  --chain PREROUTING \
  --dry-run
```

运行 benchmark：

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

运行过程中，建议先发送无害指令，例如 `CFE_ES_NOOP`。

观察攻击前后的差异时，重点看这些指标：

- command counter
- error counter
- event log
- housekeeping telemetry 是否连续
- app 是否出现异常、重启或健康状态变化

在当前 NOS3 环境里，`CFS_RADIO` 上行命令会经过 Docker 网络，最终发往类似 `172.18.0.23:6010` 或 `198.18.0.17:6010` 的 radio/cryptolib 目标。因此当发送方在 Docker 容器中时，优先使用 `PREROUTING`。只有当发送方进程直接运行在同一台 Linux 主机上时，才考虑 `OUTPUT`。

如果进程正常退出，或者收到 `Ctrl+C`，runner 会删除临时 iptables 规则。如果终端、Docker 或虚拟机异常崩溃，可以手动检查和清理规则：

```bash
sudo iptables -t nat -S OUTPUT
sudo iptables -t nat -S PREROUTING
sudo iptables -t nat -D PREROUTING -p udp -d 198.18.0.17 --dport 6010 -j REDIRECT --to-ports 19000
```

## 手动代理模式

手动模式适合本地调试，但它要求发送方直接把流量发到代理端口，而不是继续发往原始 cFS/NOS3 端点：

```bash
python3 -m cfs_security_benchmark.attacks.rf_link_proxy \
  --scenario scenarios/rf_link/link_replay.yaml \
  --listen 0.0.0.0:19000 \
  --target 198.18.0.17:6010 \
  --duration 60 \
  --log reports/rf_link_replay.jsonl
```

## 建议测试顺序

在虚拟机里建议按这个顺序测试：

1. `RF-LINK-001` 窃听基线
2. `RF-LINK-003` 延迟
3. `RF-LINK-002` 丢包
4. `RF-LINK-004` 使用 `NOOP` 做重放
5. `RF-LINK-005` 位翻转
6. `RF-LINK-007` 伪造包
7. `RF-LINK-008` 乱序
8. `RF-LINK-006` 低速率洪泛

不要一开始就做 flood。先确认 NOS3 可以正常停止和重新启动，再逐步提高攻击速率或持续时间。

## Wireshark 验证建议

抓包时优先选择当前 spacecraft Docker bridge，例如 `br-0e71bfb870b3`。不要默认抓 `any`，因为 `any` 会把同一个包在多个 veth/bridge 上重复显示。

常用显示过滤器：

```text
udp.port == 19000 || udp.port == 6010
```

其中 `19000` 是 benchmark 代理监听端口，`6010` 是当前 `CFS_RADIO` 上行目标端口。正常透明攻击链路中，通常可以看到一对包：

```text
COSMOS 容器 -> 代理端口 19000
代理/宿主机 -> 真实目标端口 6010
```

不同攻击在 Wireshark 里的典型现象：

- 窃听：两边都有包，payload 不变。
- 丢包：能看到发往代理的包，但部分包没有对应的 6010 转发包。
- 延迟：发往 19000 的包和转发到 6010 的包之间有明显时间差。
- 重放：一个输入包后面出现多次 6010 转发包。
- 位翻转：19000 和 6010 的 payload 长度相同，但某个 byte/bit 发生变化。
- 洪泛：短时间内出现大量发往 6010 的随机 payload。
- 伪造包：没有对应的 COSMOS 输入包，也能看到由 benchmark 主动发出的 6010 数据包。
- 乱序：一组输入包被缓存后，转发顺序与输入顺序不一致。

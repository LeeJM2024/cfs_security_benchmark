# cFS/NOS3 安全 Benchmark

这个项目用于为 NOS3 仿真环境中的 cFS 构建一套可重复运行的安全 benchmark。目标不是只写几个攻击脚本，而是形成一个能够自动发起攻击、采集真实系统响应、输出评分报告的评测流程。

每个攻击场景都保留统一描述模型：

```text
攻击入口 -> 受影响组件 -> CPS 对应类型 -> 安全后果 -> 恢复策略 -> NOS3/cFS 注入方式
```

## 攻击域划分

完整 benchmark 按四个域分批实现：

1. RF-link security
2. Space platform security
3. Ground systems security
4. Mission operations and supply-chain security

当前版本已经实现第一批：`RF-link security`。

## 两种运行模式

项目中保留两类运行方式：

`dry-run / scenario mode`：用于检查配置、展示攻击面、生成论文描述材料，不要求真实 NOS3 系统在线。

`live-run / scripts mode`：用于在 NOS3 VM 中真正运行攻击并打分。当前正式 benchmark 使用 live-run，它会通过 COSMOS/OpenC3 自动发送 `CFE_ES_NOOP`，再根据真实网络流量、cFS 遥测和系统事件判断攻击是否成功。

## RF-link Security

RF-link 场景模拟地面系统到航天器通信链路上的攻击。在 NOS3/cFS 中，这条链路主要体现为 COSMOS/OpenC3 向 cFS 或 radio/cryptolib 目标发送 UDP 命令包。

当前实现的 8 个场景如下：

| 场景 | 攻击类型 | 主要验证依据 |
| --- | --- | --- |
| RF-LINK-001 | Eavesdropping / 窃听 | 命令流量被透明代理捕获，同时系统仍收到有效 NOOP |
| RF-LINK-002 | Packet drop / 丢包 | 代理收到命令但不转发，系统收到的有效命令数低于发送数 |
| RF-LINK-003 | Delay / 延迟 | 命令经过代理延迟后才到达目标 |
| RF-LINK-004 | Replay / 重放 | 一次 COSMOS 命令触发多次到达目标的命令效果 |
| RF-LINK-005 | Bit flip / 位翻转 | 命令包被修改，cFS 不再按有效 NOOP 正常处理 |
| RF-LINK-006 | Flood / 洪泛 | 目标侧出现大量伪造 UDP 输入流量 |
| RF-LINK-007 | Fabricated packet / 伪造包 | 非 COSMOS 正常命令源向目标注入伪造数据包 |
| RF-LINK-008 | Reordering / 乱序 | 代理缓存多个命令后改变转发顺序 |

## 整体自动测试

在 NOS3 已经启动、COSMOS/OpenC3 图形界面已经打开后，进入 benchmark 目录：

```bash
cd "/home/leejm/Space OS/cfs-security-benchmark"
```

运行完整 RF-link benchmark：

```bash
python3 -m cfs_security_benchmark.runner.run_live_rf_link \
  --link debug \
  --all \
  --duration 4 \
  --command-wait 0.5 \
  --telemetry-timeout 5 \
  --skip-final-health
```

`--link debug` 表示测试 COSMOS 的 `CFS` debug 命令链路，目标通常是 `nos-fsw:5012`。如果要测试 radio 链路，可以改成：

```bash
python3 -m cfs_security_benchmark.runner.run_live_rf_link \
  --link radio \
  --all \
  --duration 4 \
  --command-wait 0.5 \
  --telemetry-timeout 5 \
  --skip-final-health
```

debug 链路是当前主要验证链路；radio 链路已经支持自动发现和运行，但建议先单项验证后再作为正式结果使用。

## 运行结果

整体测试会在 `runs/` 下生成一次新的运行目录，例如：

```text
runs/20260608_135216_rf_link/
```

终端会按场景打印结果，形式类似：

```text
scenario: RF-LINK-001 RF link eavesdropping baseline
commands: 1
RF-LINK-001: PASS
  evidence: system=1/1, cosmos_counter=1, cfs_noop=1, cfs_errors=0
  traffic: dnat=1, proxy_entry=1, proxy_forwarded=1, target_entry=0

BATCH RESULT: 8/8 passed
summary: /home/leejm/Space OS/cfs-security-benchmark/runs/.../summary.md
```

其中：

| 字段 | 含义 |
| --- | --- |
| `system` | 真实系统响应是否符合该场景预期 |
| `cosmos_counter` | COSMOS 遥测中 `CMDCOUNTER` 的变化 |
| `cfs_noop` | cFS 事件中观察到的 NOOP 处理数量 |
| `cfs_errors` | cFS 事件中观察到的错误或异常数量 |
| `dnat` | 透明重定向规则命中的证据 |
| `proxy_entry` | 攻击代理实际收到的包数量 |
| `proxy_forwarded` | 攻击代理实际转发的包数量 |
| `target_entry` | 目标侧抓包或计数证据 |

`dnat` 证明流量进入了透明代理路径，但由于 UDP 和 NAT 连接跟踪的存在，它不一定等于所有命令包数量。正式判定会综合代理日志、目标侧流量、cFS 事件和 COSMOS 遥测。

## 报告文件

每次 live-run 会输出：

| 文件 | 用途 |
| --- | --- |
| `summary.md` | 人可读的总报告 |
| `summary.json` | 机器可解析的总结果 |
| `*/score.json` | 单个场景的 PASS/FAIL 和指标 |
| `*/dnat_evidence.json` | 透明重定向证据 |
| `*/system_response.json` | cFS/COSMOS 的真实系统响应 |
| `*/packet_summary.json` | 抓包与代理流量摘要 |
| `*/proxy.jsonl` | 攻击代理逐包日志 |

正式 benchmark 的打分不依赖旧的 `reports/` 目录。`reports/` 只适合保留手动实验日志，不作为自动评分依据。

## 单项测试

也可以只运行一个场景：

```bash
python3 -m cfs_security_benchmark.runner.run_live_rf_link \
  --link debug \
  --scenario RF-LINK-001 \
  --duration 4 \
  --command-wait 0.5 \
  --telemetry-timeout 5 \
  --skip-final-health
```

把 `RF-LINK-001` 换成其他场景编号即可。

## Dry-run 预览

如果只想查看场景定义，不连接真实 NOS3/cFS：

```bash
python3 -m cfs_security_benchmark.runner.run_benchmark \
  --domain rf_link \
  --dry-run
```

这个模式只用于理解攻击面和检查 YAML 场景，不代表真实攻击已经发生。

## 代码结构

| 路径 | 说明 |
| --- | --- |
| `scenarios/rf_link/` | RF-link 场景定义 |
| `cfs_security_benchmark/live/environment.py` | 自动发现 COSMOS、目标容器、目标 IP、端口和 Docker bridge |
| `cfs_security_benchmark/live/cosmos_driver.py` | 通过 COSMOS/OpenC3 Ruby API 自动发送命令和读取遥测 |
| `cfs_security_benchmark/live/raw_capture.py` | 原始 UDP 抓包与证据解析 |
| `cfs_security_benchmark/runner/run_live_rf_link.py` | 正式 live benchmark 入口 |
| `scripts/rf_link/` | 已验证过的单场景辅助脚本 |

## 端口与目标自动发现

live-run 不要求用户手动写死目标 IP。程序会根据 NOS3/COSMOS 当前运行状态自动发现：

| 链路 | COSMOS Target | 目标服务 | UDP 端口 |
| --- | --- | --- | --- |
| debug | `CFS` | `nos-fsw` | `5012` |
| radio | `CFS_RADIO` | `cryptolib` | `6010` |

自动发现过程主要包括：

```text
docker exec cosmos-openc3-operator-1 getent hosts <target>
docker exec cosmos-openc3-operator-1 ip route get <target-ip>
docker inspect / docker network inspect
```

因此同一份 benchmark 可以适应不同机器上 Docker 网络 IP 的变化。

## 目前不足之处

在 scripts/rf_link 文件夹下每个攻击的单独手动测试脚本可正常运行，但需要用户自己在 nos3 系统下的图形界面手动发包，以及在 wireshark 
中看是否有预期结果出现。而全自动化流程虽已找到 nos3 文件夹下发包收包入口代码，但目前还不能稳定实现全自动化流程检测（要么时间窗口开的较久，要么窗口太短无法收到全部包）。
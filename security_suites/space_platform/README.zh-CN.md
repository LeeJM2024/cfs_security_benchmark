# 空间平台安全套件

[English](README.md) | [简体中文](README.zh-CN.md)

`injections/` 中包含 8 个真实 NOS3/cFS 注入包。每个包均有安装器、验证器和卸载器；基于应用的用例还包含 cFS 飞行软件与 COSMOS/OpenC3 字典工件。

| ID | 攻击类别 |
| --- | --- |
| SP001 | 软件总线指令欺骗 |
| SP002 | 畸形遥控注入 |
| SP003 | 应用生命周期、崩溃与重启压力 |
| SP004 | 飞行软件表篡改 |
| SP005 | 组件/源配置污染 |
| SP006 | 载荷与关键接口滥用 |
| SP007 | CPU、总线、事件、存储和 IPC 资源耗尽 |
| SP008 | 子系统状态与遥测欺骗 |

## 生命周期

安装注入包，再按正常流程构建并启动 NOS3：

```bash
python3 -m benchmark_engine.lifecycle.prep \
  --nos3-root /home/leejm/nos3 --domains space_platform
cd /home/leejm/nos3 && make config && make fsw && make launch
```

clean 阶段运行 SP001–SP004 和 SP006–SP008。除非明确选择并确认，否则会排除危险的 SP001 配置：

```bash
python3 -m benchmark_engine.space_platform.verify_all --phase clean
python3 -m benchmark_engine.space_platform.verify_all \
  --sp001-risk all --confirm-hazard --phase clean
```

SP005 被刻意隔离：应用所有字段级修改、重建/重启、验证、恢复，再次重建/重启。

```bash
python3 -m benchmark_engine.space_platform.verify_all --prepare-sp005
# 在 NOS3 中执行：make config && make fsw && make sim；重启 NOS3/cFS/模拟器
python3 -m benchmark_engine.space_platform.verify_all --phase sp005
python3 -m benchmark_engine.space_platform.verify_all --restore-sp005
```

测试后按反向包顺序卸载：

```bash
python3 -m benchmark_engine.lifecycle.cleanup \
  --nos3-root /home/leejm/nos3 --domains space_platform
```

不要将验证器自身的日志视为成功证据：验证器会依据目标的原生遥测、事件、文件、表、配置或运行时状态评分。各包的具体步骤记录在相应注入目录中。

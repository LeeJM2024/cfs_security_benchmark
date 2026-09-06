# RF-Link Security Suite

[English](README.md) | [简体中文](README.zh-CN.md)

This suite evaluates attacks on the UDP command and telemetry path between the ground system and NOS3/cFS communication interfaces. A benchmark identifier is executed as both an `uplink` and a `downlink` case; the two directions share one ID but retain separate evidence.

## Implemented scenarios

| ID | Scenario |
| --- | --- |
| RF-LINK-001 | Eavesdropping and forwarding baseline |
| RF-LINK-002 | Probabilistic packet drop |
| RF-LINK-003 | Packet delay |
| RF-LINK-004 | Observed-packet replay |
| RF-LINK-005 | Packet bit flip |
| RF-LINK-006 | Bounded packet flood |
| RF-LINK-007 | Attacker-controlled fabricated packet |
| RF-LINK-008 | Buffered packet reordering |

`scenarios/` stores the executable definitions; `threat_models/` defines the trusted-domain and cryptographic-boundary assumptions; `scripts/run_live_cases.sh` is the shell entry point for the live runner.

## Run safely

First inspect a scenario without changing network rules:

```bash
python3 -m benchmark_engine.rf_link.simulator_runner \
  --scenario security_suites/rf_link/scenarios/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 --listen-port 19000 \
  --transparent --chain PREROUTING --dry-run
```

Run the formal radio-link matrix only in the NOS3 VM:

```bash
python3 -m benchmark_engine.rf_link.live_runner \
  --all --link radio --direction both
```

For transparent interception, the sender still targets the original UDP endpoint. The runner installs a scoped temporary redirect, starts the proxy, forwards marked proxy traffic to the real target, captures evidence, and removes the rule on normal completion. Use `PREROUTING` when the sender is in Docker; use `OUTPUT` only for a local sender on the proxy host. After an interrupted run, inspect and remove stale rules before continuing. Detailed topology, manual-proxy use, and the recommended low-risk test order are in `../../docs/rf_link.md`.

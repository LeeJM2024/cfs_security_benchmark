# RF-link Security Implementation Notes

## Research Model

The RF-link batch uses this common benchmark description:

```text
attack entry -> affected component -> CPS type -> security consequence -> recovery strategy -> NOS3/cFS injection method
```

For RF-link security, the typical path is:

```text
RF-link / UDP endpoint
-> COM interface / CI / TO / radio interface
-> Communication
-> data leak, denial of control, replayed control, forged packet, or malformed packet
-> retransmission, authentication, freshness check, rate limit, parser rejection, safe mode
-> UDP attack proxy between ground system and cFS/NOS3 endpoint
```

## Implemented Scenarios

| ID | Attack | Effect |
| --- | --- | --- |
| RF-LINK-001 | Eavesdropping | Logs and forwards packets in both directions |
| RF-LINK-002 | Packet drop | Drops uplink TC or downlink TM packets with a probability |
| RF-LINK-003 | Packet delay | Delays uplink TC or downlink TM forwarding |
| RF-LINK-004 | Packet replay | Replays observed command or telemetry packets |
| RF-LINK-005 | Bit flip | Mutates a command or telemetry packet bit |
| RF-LINK-006 | Packet flood | Sends attacker traffic to the selected receiver |
| RF-LINK-007 | Fabricated packet | Sends attacker-controlled payload to the selected receiver |
| RF-LINK-008 | Packet reordering | Buffers and shuffles command or telemetry packets |

The IDs remain the eight benchmark identifiers. Each live run emits an
`uplink` case and a `downlink` case under the same identifier rather than
allocating sixteen scenario IDs.

## Live Direction Cases

Use the live runner for formal NOS3 execution:

```bash
python3 -m benchmark_engine.rf_link.live_runner \
  --all \
  --link radio \
  --direction both
```

For `radio`, the runner discovers the active cryptolib container and creates a
temporary DNAT rule in its network namespace:

```text
cryptolib:<ephemeral-source> -> COSMOS:6011
-> cryptolib OUTPUT DNAT -> host proxy:19001
-> COSMOS:6011
```

The downlink case sends `GENERIC_EPS_RADIO GENERIC_EPS_REQ_HK` as a normal,
repeatable telemetry stimulus and observes `GENERIC_EPS_HK_TLM CMD_COUNT`.
The rule, proxy, packet capture, and receiver counter are scoped to the case
and removed when it ends.

`bash security_suites/rf_link/scripts/run_live_cases.sh` is the matching helper for the live
runner. By default it runs all eight identifiers in both directions; use
`DIRECTION=downlink` or `SCENARIO=RF-LINK-004` to narrow it.

## Transparent Mode With NOS3/cFS

The benchmark should not require manual COSMOS/YAMCS reconfiguration. Use
transparent mode for formal runs:

```text
COSMOS/YAMCS
-> original target, such as 198.18.0.17:6010
-> iptables redirects matching UDP packets to the local proxy
-> RF-link attack proxy
-> original target, such as 198.18.0.17:6010
```

The proxy uses a Linux socket mark for packets that it sends to the real target.
The iptables rule ignores marked packets, which prevents a redirect loop.

Preview the rule:

```bash
python3 -m benchmark_engine.rf_link.simulator_runner \
  --scenario security_suites/rf_link/scenarios/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 \
  --listen-port 19000 \
  --transparent \
  --chain PREROUTING \
  --dry-run
```

Run the benchmark:

```bash
sudo python3 -m benchmark_engine.rf_link.simulator_runner \
  --scenario security_suites/rf_link/scenarios/link_eavesdrop.yaml \
  --target 198.18.0.17:6010 \
  --listen-port 19000 \
  --transparent \
  --chain PREROUTING \
  --duration 60 \
  --log artifacts/reports/rf_link_eavesdrop_nos3.jsonl
```

During the run, send a harmless command first, such as `CFE_ES_NOOP`.

Compare baseline and attack behavior:

   - command counter
   - error counter
   - event log
   - housekeeping telemetry continuity
   - app health or restart events

Your observed `CFE_ES_NOOP` packet came from a Docker-side address
(`192.168.41.2`) toward `198.18.0.17:6010`, so `--chain PREROUTING` is the
right first choice. Use `--chain OUTPUT` only when the sender process runs
directly on the same Linux host, not in a Docker container.

If the process exits normally or receives `Ctrl+C`, the runner removes the
iptables rule. If the terminal or VM crashes, manually inspect and clean rules:

```bash
sudo iptables -t nat -S OUTPUT
sudo iptables -t nat -S PREROUTING
sudo iptables -t nat -D PREROUTING -p udp -d 198.18.0.17 --dport 6010 -j REDIRECT --to-ports 19000
```

## Manual Proxy Mode

Manual mode is still useful for local debugging, but it requires the sender to
send traffic directly to the proxy:

```bash
python3 -m benchmark_engine.rf_link.proxy \
  --scenario security_suites/rf_link/scenarios/link_replay.yaml \
  --listen 0.0.0.0:19000 \
  --target 198.18.0.17:6010 \
  --duration 60 \
  --log artifacts/reports/rf_link_replay.jsonl
```

## Safe Testing Order

Use this order in the VM:

1. `RF-LINK-001` eavesdropping baseline
2. `RF-LINK-003` delay
3. `RF-LINK-002` drop
4. `RF-LINK-004` replay with `NOOP`
5. `RF-LINK-005` bit flip
6. `RF-LINK-007` fabricated packet
7. `RF-LINK-008` reorder
8. `RF-LINK-006` flood at low rate

Do not start with flood. Confirm that NOS3 can be stopped and relaunched before
raising attack rate or duration.

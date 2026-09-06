# cFS/NOS3 rf_link Security Benchmark Scenario Index

## Scope

- Scenario count: `8`
- Complete description schema: `8/8`
- Mode: `dry-run / scenario index`

## Scenario Matrix

| Scenario | Entry | Component | CPS Type | Injection | Metrics |
| --- | --- | --- | --- | --- | --- |
| `RF-LINK-005` RF link bit flip | RF-link / ground-to-space command or downlink telemetry path | COM interface, TC parser, telemetry parser | Communication | UDP proxy flips a configured bit in selected packets | packet_received, packet_forwarded, error_counter, parser_event_log |
| `RF-LINK-003` RF link command delay | RF-link / ground-to-space command path | COM interface, TC fetcher, cFS command dispatch | Communication | UDP proxy sleeps before forwarding selected packets | packet_received, packet_forwarded, command_latency, event_log |
| `RF-LINK-002` RF link packet drop | RF-link / ground-to-space command path | COM interface, TC fetcher, CI app | Communication | UDP proxy probabilistically drops packets before forwarding | packet_received, packet_forwarded, command_counter, telemetry_continuity |
| `RF-LINK-001` RF link eavesdropping baseline | RF-link / ground-to-space UDP command or telemetry path | COM interface, CI/TO link, radio interface | Communication | UDP proxy logs packets and forwards them unchanged | packet_received, packet_forwarded, event_log |
| `RF-LINK-007` RF link fabricated packet | RF-link / ground-to-space command path | COM interface, TC fetcher, CI app | Communication | UDP proxy sends attacker-controlled payload bytes to the target endpoint | packet_fabricated, error_counter, event_log |
| `RF-LINK-006` RF link command flood | RF-link / ground-to-space command path | COM interface, CI app, cFE Software Bus, cFS apps | Communication | UDP proxy sends random packets to the target endpoint at a configured rate | packet_flooded, cpu_load, command_error_counter, app_health |
| `RF-LINK-008` RF link packet reordering | RF-link / ground-to-space command path | COM interface, TC fetcher, cFS command handlers | Communication | UDP proxy buffers a small window of packets and forwards them in random order | packet_received, packets_reordered, command_sequence, event_log |
| `RF-LINK-004` RF link command replay | RF-link / ground-to-space command path | COM interface, CI app, cFS command handlers | Communication | UDP proxy duplicates observed command packets | packet_received, packet_forwarded, command_counter, error_counter, event_log |

## Required Description Chain

`attack_entry -> affected_component -> cps_type -> security_consequence -> recovery_strategy -> injection_method`

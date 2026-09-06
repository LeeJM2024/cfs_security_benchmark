# cFS/NOS3 space_platform Security Benchmark Scenario Index

## Scope

- Scenario count: `8`
- Complete description schema: `8/8`
- Mode: `dry-run / scenario index`

## Scenario Matrix

| Scenario | Entry | Component | CPS Type | Injection | Metrics |
| --- | --- | --- | --- | --- | --- |
| `SP-003` cFS app crash and restart pressure | Space platform app runtime / cFE Executive Services | cFS app process, cFE ES restart and exception handling | Controller | Send BENCH_VICTIM_INJECT_FAULT through COSMOS/CI, let the cFS app exit with APP_ERROR, then observe cFE/FSW recovery and BENCH_VICTIM telemetry returning | app_fault_injected, victim_unresponsive_after_fault, automatic_fsw_recovery, victim_responsive_after_recovery |
| `SP-002` Malformed TC parser and command handler input | Space platform TC parser / command handler boundary | CI, cFE command dispatcher, app command handlers | Controller | In dry-run mode generate malformed TC payload bytes; in live mode send malformed BENCH_ATTACK/BENCH_VICTIM commands through COSMOS/CI and verify cFS command error counters increase while spoof delivery is blocked | malformed_tc_generated, command_error_expected, event_log, attack_command_error_delta, victim_command_error_delta, attack_spoof_delta |
| `SP-005` Payload critical interface abuse | Space platform payload or PDHS interface | BENCH_PAYLOAD app, PDHS boundary, bus-payload link | Controller | In dry-run mode generate a critical payload command artifact; in live mode send BENCH_PAYLOAD_START_COLLECTION without arming and verify the cFS payload guard rejects it | payload_command_generated, critical_interface_touched, unauthorized_command_delta, collection_start_delta, payload_mode |
| `SP-007` OBSW runtime resource exhaustion | Space platform OS/runtime resource boundary | cFS Software Bus, BENCH_ATTACK, BENCH_VICTIM, app runtime | Controller | In dry-run mode generate a pressure plan; in live mode trigger bounded BENCH_ATTACK Software Bus flood and validate recovery by HK/NOOP telemetry | resource_pressure_planned, throttling_expected, flood_sent_delta, victim_received_delta, post_attack_noop_response |
| `SP-006` Scheduler manipulation and timing disruption | Benchmark scheduler control command path | BENCH_SCHED app, BENCH_PERIODIC telemetry model, Software Bus tick message | Controller | Live cFS benchmark scheduler app disables a Software Bus tick, periodic task reports missed deadlines through HK telemetry | baseline_tick_received_delta, missed_deadline_delta, restored_tick_received_delta, post_attack_noop_health |
| `SP-001` Software Bus spoofed internal message | Space platform internal interface / cFS Software Bus | cFE SB, subscribed cFS apps, mission application message handlers | Controller | In dry-run mode generate a spoofed SB message artifact; in live mode send BENCH_ATTACK_SEND_SPOOF through COSMOS/CI and verify BENCH_VICTIM receives BENCH_SPOOF_INTERNAL_MID through cFE SB telemetry | software_bus_message_spoofed, artifact_written, event_log, bench_attack_spoof_sent_delta, bench_victim_spoof_received_delta, last_payload_word |
| `SP-008` Satellite subsystem state spoofing | Benchmark subsystem state command path | EPS state model, subsystem telemetry consumer, plausibility monitor | Sensor / actuator / physical state | Live cFS benchmark app publishes plausible and spoofed EPS states, then reports plausibility failures through HK telemetry | spoofed_state_delta, plausibility_error_delta, state_trusted_flag, post_attack_noop_health |
| `SP-004` Table and configuration tampering | Space platform table/configuration interface | cFE TBL, mission app configuration tables, control parameters | Controller | In dry-run mode generate a tampered table artifact; in live mode load /cf/bench_bad.tbl through cFE TBL commands and verify BENCH_VICTIM validation rejects the active table update | table_parameter_tampered, artifact_written, event_log, table_validation_failure_delta, active_table_value_preserved, table_update_count |

## Required Description Chain

`attack_entry -> affected_component -> cps_type -> security_consequence -> recovery_strategy -> injection_method`

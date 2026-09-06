# Supply-Chain Security Suite

The supply-chain suite is scaffolded under `security_suites/supply_chain/`.
It has two tracks:

1. malicious vendor-style cFS applications installed through the real NOS3
   component/build/startup flow;
2. flight and ground mission artifacts that reuse the existing SP004, SP005,
   GS002, and GS004 real-effect verifiers.

The app architecture matrix models single/colluding components, static/real
NOVATEL-driven triggers, Software Bus coordination, and a POSIX FIFO variant.
The payload matrix references SP001, SP003, SP006, SP007, and SP008, plus
telemetry exfiltration through the existing TO_LAB/radio-sim path.

The vendor app carrier, NOS3 installer, and first COSMOS verifier are present;
the installer is not invoked automatically. Existing SP/GS payload adapters,
the full profile dispatcher, and release-manifest enforcement remain to be
connected.

## Dynamic-NOVATEL recovery helper

If a dynamic vendor profile stops receiving NOVATEL packets after an earlier
simulation run, execute the local NOS3 recovery helper **inside the NOS3 VM**:

```bash
cd /home/leejm/Space\ OS/cfs-security-benchmark
python3 security_suites/supply_chain/nos3_dynamic_recover.py --json
```

It restarts only the NOS Engine, GPS simulator, FSW, and time-driver in the
required `Engine -> GPS -> FSW -> time-driver` order. It never starts, stops,
or restarts COSMOS/CmdTlmServer. Use `--dry-run` to preview actions. A successful
result confirms cFE operational state plus CI and TO readiness; then run a
declared dynamic profile to prove the live NOVATEL path.

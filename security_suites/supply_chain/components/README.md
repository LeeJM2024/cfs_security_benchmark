# SC-APP Components

[English](README.md) | [简体中文](README.zh-CN.md)

These are real cFS applications, not benchmark-only victims. The installer copies them into the NOS3 component tree, registers them in the mission targets/startup configuration, and the normal NOS3 build produces the runnable modules and COSMOS dictionaries.

`sc_vendor_nav` is the primary carrier: it observes static time or NOVATEL telemetry, maintains a benign diagnostic interface, and drives the selected payload after its trigger. `sc_vendor_diag` is the second carrier used by colluding profiles; it participates through a Software Bus message or POSIX FIFO. Verifiers must observe native NOS3 state, TO_LAB/radio-sim output, COSMOS evidence, or actual cFS state—not self-reported malicious telemetry alone.

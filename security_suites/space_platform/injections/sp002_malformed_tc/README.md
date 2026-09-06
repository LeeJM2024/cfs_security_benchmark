# SP002 — Malformed Telecommand Injection

[English](README.md) | [简体中文](README.zh-CN.md)

SP002 sends deliberately malformed CCSDS telecommands to real cFS/NOS3 command interfaces and evaluates the parser, command counters, events and target state. `sp002_run_live.py` is the package entry point: it copies the raw-packet sender and Ruby verifier into the operator container, discovers the required return path, and supports selected profile IDs and safe/hazardous modes.

Install and remove the package through `install_into_nos3.py` and `uninstall_from_nos3.py`; use the shared space-platform lifecycle for a full campaign. Hazardous modes require explicit confirmation in the runtime runner.

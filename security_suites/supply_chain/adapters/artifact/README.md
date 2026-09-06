# SC-ART Adapters

[English](README.md) | [简体中文](README.zh-CN.md)

Artifact adapters execute an exact filesystem transaction around the signed release manifest and then invoke the corresponding native verifier:

- SC-ART-001/002 stage the release, require the NOS3 build/relaunch checkpoint, and verify through SP004/SP005. Rollback restores pre-release bytes.
- SC-ART-003/004 modify only their declared mounted COSMOS files. The runner emits a CmdTlmServer reload checkpoint; it never starts, stops or restarts that service. The operator reloads it and explicitly confirms before verification/rollback.
- SC-ART-005 audits native release ingress. Its clean/revoked/version fixtures are not deployed through the optional gate; missing release admission is an attack PASS with a remediation recommendation.

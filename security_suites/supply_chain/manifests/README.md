# SC-ART Release Manifests

[English](README.md) | [简体中文](README.zh-CN.md)

This directory contains the signed release inputs for the artifact track. A schema-v1 manifest binds a release ID, supplier, version and compatibility information, immutable content hashes, declared target operations, lifecycle requirements, and a local benchmark HMAC signature. `trust_anchors.json` is a repeatable-test fixture, not a production key-management system.

`poisoned/` contains the executable SC-ART-001 through SC-ART-004 releases. `clean/` and `revoked/` provide SC-ART-005 clean, revoked and rollback/version inputs for both table and component-configuration releases. The optional release gate validates signature, digest, revocation and policy before a transaction writes a NOS3 path; each transaction snapshots its declared targets and restores exact bytes on error or rollback.

SC-ART-005 tests native NOS3 ingress instead. Its fixtures are not deployed through the optional gate: a release-admission hook that accepts a revoked or mismatched release is the target condition under test.

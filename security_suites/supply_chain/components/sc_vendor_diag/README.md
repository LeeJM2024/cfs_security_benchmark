# sc_vendor_diag

[English](README.md) | [简体中文](README.zh-CN.md)

The secondary vendor-style diagnostic cFS application for colluding SC-APP profiles. It publishes benign housekeeping and receives the coordination signal from `sc_vendor_nav`: a custom cFS Software Bus message for SC-APP-003/004 or a POSIX FIFO signal for SC-APP-005 on amd64-posix. It is not needed for the single-component profiles.

Its flight-software and COSMOS/OpenC3 dictionary artifacts are installed by the suite installer with `sc_vendor_nav`.

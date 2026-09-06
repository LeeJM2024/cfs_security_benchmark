# sc_vendor_nav

[English](README.md) | [简体中文](README.zh-CN.md)

The primary vendor-style navigation/health cFS application used by SC-APP. It publishes benign diagnostic housekeeping, supports static and NOVATEL-driven trigger paths, and is the one-component carrier for SC-APP-001/002. In colluding profiles it originates the Software Bus or FIFO coordination signal and exposes the six selectable supply-chain payload adapters.

Its FSW source is under `fsw/cfs/`; `gsw/cosmos/cmd_tlm/SC_VENDOR_NAV.txt` supplies the COSMOS/OpenC3 command and telemetry dictionary. Install it through the suite installer rather than copying its files piecemeal.

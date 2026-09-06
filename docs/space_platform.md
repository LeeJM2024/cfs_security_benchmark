# Space-Platform Security Suite

This suite contains the current Space-platform implementation: eight real
NOS3/cFS injection packages, SP001 through SP008. Each package owns
  its install, verify, and uninstall scripts together with its FSW and COSMOS
  artifacts.

The shared lifecycle installs every registered package before a manual NOS3
build and launch:

```bash
python3 -m benchmark_engine.lifecycle.prep --nos3-root /home/leejm/nos3
```

After `make config`, `make fsw`, and `make launch`, run all eight Ruby
verifiers in COSMOS:

```bash
python3 -m benchmark_engine.space_platform.verify_all
```

Use the shared cleanup after the run:

```bash
python3 -m benchmark_engine.lifecycle.cleanup --nos3-root /home/leejm/nos3
```

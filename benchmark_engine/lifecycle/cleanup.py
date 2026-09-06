from __future__ import annotations

import argparse
from pathlib import Path

from benchmark_engine.lifecycle.registry import DOMAIN_ORDER, run_lifecycle


def main() -> None:
    parser = argparse.ArgumentParser(description="Uninstall all registered benchmark prerequisites from NOS3")
    parser.add_argument("--nos3-root", type=Path, default=Path("/home/leejm/nos3"))
    parser.add_argument("--domains", nargs="+", choices=DOMAIN_ORDER, default=list(DOMAIN_ORDER))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    raise SystemExit(0 if run_lifecycle(action="cleanup", nos3_root=args.nos3_root, domains=args.domains, dry_run=args.dry_run) else 1)


if __name__ == "__main__":
    main()

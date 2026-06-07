from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from contextlib import AbstractContextManager
from pathlib import Path

from cfs_security_benchmark.attacks.rf_link_proxy import Endpoint, EventLog, RfLinkProxy
from cfs_security_benchmark.scenario import load_scenario


DEFAULT_PROXY_MARK = 0xCF5B


class IptablesRedirect(AbstractContextManager["IptablesRedirect"]):
    def __init__(
        self,
        target: Endpoint,
        listen_port: int,
        mark: int,
        source: str | None,
        chain: str,
        redirect_mode: str,
        proxy_host: str | None,
        dry_run: bool,
    ):
        self.target = target
        self.listen_port = listen_port
        self.mark = mark
        self.source = source
        self.chain = chain.upper()
        self.redirect_mode = redirect_mode.upper()
        self.proxy_host = proxy_host
        self.dry_run = dry_run
        self.iptables_prefix = _iptables_prefix()

    def __enter__(self) -> "IptablesRedirect":
        self._run(self._insert_command())
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._run(self._delete_command(), check=False)

    def _rule_body(self) -> list[str]:
        rule = [
            self.chain,
            "-p",
            "udp",
            "-d",
            self.target.host,
            "--dport",
            str(self.target.port),
        ]
        if self.chain == "OUTPUT":
            rule.extend(["-m", "mark", "!", "--mark", str(self.mark)])
        if self.source:
            rule.extend(["-s", self.source])
        if self.redirect_mode == "DNAT":
            if not self.proxy_host:
                raise ValueError("--proxy-host is required when --redirect-mode DNAT is used")
            rule.extend(["-j", "DNAT", "--to-destination", f"{self.proxy_host}:{self.listen_port}"])
        else:
            rule.extend(["-j", "REDIRECT", "--to-ports", str(self.listen_port)])
        return rule

    def _insert_command(self) -> list[str]:
        return [*self.iptables_prefix, "-t", "nat", "-A", *self._rule_body()]

    def _delete_command(self) -> list[str]:
        return [*self.iptables_prefix, "-t", "nat", "-D", *self._rule_body()]

    def _run(self, command: list[str], check: bool = True) -> None:
        print("+ " + " ".join(command), flush=True)
        if self.dry_run:
            return
        subprocess.run(command, check=check)


class NullContext(AbstractContextManager["NullContext"]):
    def __enter__(self) -> "NullContext":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def _iptables_prefix() -> list[str]:
    if shutil.which("iptables"):
        return ["iptables"]
    if shutil.which("nsenter"):
        return ["nsenter", "-t", "1", "-m", "-n", "/usr/sbin/iptables"]
    return ["iptables"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an RF-link benchmark scenario")
    parser.add_argument("--scenario", required=True, help="Path to RF-link scenario YAML/JSON")
    parser.add_argument("--target", type=Endpoint.parse, required=True, help="Original NOS3/cFS UDP target, host:port")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Proxy listen host")
    parser.add_argument("--listen-port", type=int, default=19000, help="Proxy listen UDP port")
    parser.add_argument("--duration", type=float, help="Stop automatically after this many seconds")
    parser.add_argument("--log", type=Path, default=Path("reports/rf_link_transparent.jsonl"), help="JSONL event log")
    parser.add_argument("--seed", type=int, default=7, help="Deterministic seed for probabilistic attacks")
    parser.add_argument("--source", help="Optional source IP filter, such as the COSMOS container IP")
    parser.add_argument("--redirect-mode", choices=("REDIRECT", "DNAT"), default="REDIRECT", help="iptables redirect method")
    parser.add_argument("--proxy-host", help="Host IP that Docker-originated packets can reach, required for DNAT mode")
    parser.add_argument(
        "--chain",
        choices=("PREROUTING", "OUTPUT"),
        default="PREROUTING",
        help="iptables NAT chain. Use PREROUTING for Docker/container-originated packets, OUTPUT for local host processes.",
    )
    parser.add_argument("--mark", type=lambda value: int(value, 0), default=DEFAULT_PROXY_MARK, help="SO_MARK value used to prevent redirect loops")
    parser.add_argument("--transparent", action="store_true", help="Enable iptables transparent interception")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without changing iptables or binding sockets")
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    listen = Endpoint(args.listen_host, args.listen_port)

    print(f"scenario: {scenario.id} {scenario.name}")
    print(f"proxy listen: {listen.host}:{listen.port}")
    print(f"real target: {args.target.host}:{args.target.port}")
    print(f"transparent: {args.transparent}")

    if args.transparent:
        redirect_context: AbstractContextManager = IptablesRedirect(
            target=args.target,
            listen_port=listen.port,
            mark=args.mark,
            source=args.source,
            chain=args.chain,
            redirect_mode=args.redirect_mode,
            proxy_host=args.proxy_host,
            dry_run=args.dry_run,
        )
    else:
        redirect_context = NullContext()

    if args.dry_run:
        with redirect_context:
            pass
        print("dry run complete")
        return

    with redirect_context:
        proxy = RfLinkProxy(
            scenario=scenario,
            listen=listen,
            target=args.target,
            reverse_listen=None,
            log=EventLog(args.log),
            seed=args.seed,
            socket_mark=args.mark if args.transparent and args.chain == "OUTPUT" else None,
        )
        proxy.run(duration_seconds=args.duration)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"iptables command failed with exit code {exc.returncode}", file=sys.stderr)
        raise SystemExit(exc.returncode)

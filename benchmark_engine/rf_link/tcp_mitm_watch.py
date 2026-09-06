"""Host-only watcher that rearms the external MITM after a user NOS3 launch."""
from __future__ import annotations

import argparse, json, os, subprocess, time
from pathlib import Path

from benchmark_engine.nos3.environment import discover_cryptographic_boundary_environment_host_only
from benchmark_engine.rf_link.tcp_mitm_session import ROOT, _host_veth, _iptables, control
from benchmark_engine.rf_link.threat_models import load_threat_model


def _start_proxy(*, uplink: str, downlink: str, state: Path, log: Path, up_port: int, down_port: int, control_port: int) -> int:
    pid_file = state.with_suffix('.pid')
    if pid_file.exists():
        try: os.kill(int(pid_file.read_text().strip()), 15)
        except (ProcessLookupError, ValueError): pass
    with state.with_suffix('.proxy.stdout.log').open('ab') as output:
        process = subprocess.Popen(['python3', '-m', 'benchmark_engine.rf_link.tcp_mitm', '--uplink-target', uplink,
            '--downlink-target', downlink, '--uplink-port', str(up_port), '--downlink-port', str(down_port),
            '--control-port', str(control_port), '--log', str(log)], cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=output, stderr=output, start_new_session=True)
    pid_file.write_text(str(process.pid) + '\n', encoding='utf-8')
    for _ in range(20):
        try: control(control_port, {'action': 'snapshot'}); return process.pid
        except OSError: time.sleep(.25)
    raise RuntimeError('new host proxy did not become ready')


def main() -> None:
    p = argparse.ArgumentParser(); p.add_argument('--state', type=Path, required=True); p.add_argument('--log', type=Path, required=True)
    p.add_argument('--uplink-port', type=int, default=18010); p.add_argument('--downlink-port', type=int, default=18011); p.add_argument('--control-port', type=int, default=18990)
    args = p.parse_args(); last = None
    while True:
        try:
            boundary = discover_cryptographic_boundary_environment_host_only(load_threat_model('cryptographic-boundary', ROOT))
            up, down = boundary.path_for('uplink'), boundary.path_for('downlink')
            signature = (up.source_ip, up.destination_ip, up.bridge_interface, down.source_ip, down.destination_ip, down.bridge_interface)
            if signature != last:
                old = json.loads(args.state.read_text(encoding='utf-8')) if args.state.exists() else None
                if old:
                    for direction in ('uplink', 'downlink'):
                        try: _iptables(type('OldPath', (), old['paths'][direction])(), int(old['ports'][direction]), '-D')
                        except Exception: pass
                _start_proxy(uplink=up.destination, downlink=down.destination, state=args.state, log=args.log,
                             up_port=args.uplink_port, down_port=args.downlink_port, control_port=args.control_port)
                _iptables(up, args.uplink_port, '-I'); _iptables(down, args.downlink_port, '-I')
                up_state, down_state = up.__dict__.copy(), down.__dict__.copy()
                for item, path in ((up_state, up), (down_state, down)):
                    try: item['host_veth'] = _host_veth(path)
                    except RuntimeError: item['host_veth'] = None
                args.state.write_text(json.dumps({'paths': {'uplink': up_state, 'downlink': down_state},
                    'bridge_interface': up.bridge_interface, 'control_port': args.control_port,
                    'ports': {'uplink': args.uplink_port, 'downlink': args.downlink_port},
                    'session_owner': 'suite-owned-external-tcp-mitm', 'endpoint_namespace_access': False,
                    'process_restart': False, 'watcher_rearmed_for_current_launch': True}, indent=2)+'\n', encoding='utf-8')
                print(json.dumps({'rearmed': True, 'signature': signature}), flush=True); last = signature
        except Exception as error:
            print(json.dumps({'watch_warning': str(error)}), flush=True)
        time.sleep(.5)


if __name__ == '__main__': main()

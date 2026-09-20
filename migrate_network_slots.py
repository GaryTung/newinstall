#!/usr/bin/env python3
"""Reconcile legacy index-based routes. Run with services stopped and backups saved."""
from __future__ import annotations
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

app = Path(os.environ.get('VPNGATE_APP_DIR', '/opt/aimilivpn'))
sys.path.insert(0, str(app if (app / 'channel_network.py').exists() else Path(__file__).resolve().parent))
from channel_network import ensure_network_slots, channel_network, channel_slot, slot_from_proxy_address, managed_address, valid_slot


def read(path, default):
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else default


def write(path, data):
    temp = path.with_suffix(path.suffix + '.migration-tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    os.chmod(temp, 0o600)
    temp.replace(path)


def allocate_legacy(config, state):
    """Prefer each healthy channel's actual address during the one-time migration."""
    used = {c.get('network_slot') for c in config.get('channels', []) if valid_slot(c.get('network_slot'))}
    for c in config.get('channels', []):
        runtime = state.get('channels', {}).get(c['id'], {})
        slot = slot_from_proxy_address(runtime.get('proxy_address'))
        if not valid_slot(c.get('network_slot')) and runtime.get('status') == 'connected' and slot and slot not in used:
            c['network_slot'] = slot
            used.add(slot)
    ensure_network_slots(config)


def transport_failure(record):
    error = str(record.get('error') or '').lower()
    return any(text in error for text in (
        'connection timed out', 'connection refused', 'network is unreachable',
        'no route to host', 'server poll timeout', 'openvpn timeout',
        'proxy unavailable', 'vpn 进程异常退出', '本机通道内部路由冲突',
    ))


def addresses(prefix, interface):
    p = subprocess.run([*prefix, 'ip', '-j', '-4', 'addr', 'show', 'dev', interface], text=True, capture_output=True, timeout=10)
    if p.returncode:
        if 'does not exist' in p.stderr or 'Cannot open network namespace' in p.stderr:
            return []
        raise RuntimeError(p.stderr.strip())
    return [(str(a['local']), int(a['prefixlen'])) for link in json.loads(p.stdout or '[]') for a in link.get('addr_info', [])]


def reconcile_template(template, targets):
    changed = []
    seen = set()
    for outbound in template.get('outbounds', []):
        tag = str(outbound.get('tag') or '')
        if tag not in targets:
            continue
        servers = outbound.get('settings', {}).get('servers', [])
        if outbound.get('protocol') != 'socks' or len(servers) != 1:
            raise RuntimeError(f'{tag} 出站结构异常，未修改')
        if servers[0].get('address') != targets[tag]:
            changed.append(tag)
        servers[0]['address'] = targets[tag]
        seen.add(tag)
    if set(targets) - seen:
        raise RuntimeError('缺少国家出站：' + ', '.join(sorted(set(targets) - seen)))
    return changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.apply:
        for service in ('aimilivpn', 'aimilivpn-multiexit', 'x-ui'):
            if subprocess.run(['systemctl', 'is-active', '--quiet', service]).returncode == 0:
                raise RuntimeError(f'迁移前必须停止 {service}')
    directory = Path('/var/lib/aimilivpn-multiexit')
    config_path, state_path = directory / 'channels.json', directory / 'state.json'
    config, state = read(config_path, {}), read(state_path, {})
    if not config.get('channels'):
        print(json.dumps({'migrated': False, 'reason': 'no channels'}))
        return
    allocate_legacy(config, state)
    targets, cleanup, changed_ids = {}, [], set()
    for c in config['channels']:
        cid = str(c['id'])
        if not re.fullmatch(r'[a-z0-9-]{1,12}', cid):
            raise RuntimeError('通道ID无效')
        _, host, peer = channel_network(channel_slot(c))
        if c.get('enabled', True):
            targets['VPNGATE-COUNTRY-' + cid.upper()] = peer
        interfaces = [([], ('vh-' + cid)[:15], host), (['ip', 'netns', 'exec', 'avpn-' + cid[:10]], ('vn-' + cid)[:15], peer)]
        for prefix, interface, expected in interfaces:
            for old, bits in addresses(prefix, interface):
                if managed_address(old) and (old != expected or bits != 30):
                    cleanup.append([*prefix, 'ip', 'addr', 'del', f'{old}/{bits}', 'dev', interface])
                    changed_ids.add(cid)
    database = Path('/etc/x-ui/x-ui.db')
    db = sqlite3.connect(str(database) if args.apply else f'file:{database}?mode=ro', uri=not args.apply)
    row = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
    template = json.loads(row[0])
    changed_tags = reconcile_template(template, targets)
    changed_ids.update(c['id'] for c in config['channels'] if 'VPNGATE-COUNTRY-' + c['id'].upper() in changed_tags)
    failed_countries = {c['country'] for c in config['channels'] if c['id'] in changed_ids and state.get('channels', {}).get(c['id'], {}).get('status') != 'connected'}
    node_path = Path('/var/lib/aimilivpn/nodes.json')
    if not node_path.exists():
        node_path = app / 'vpngate_data/nodes.json'
    affected_nodes = {str(n['id']) for n in read(node_path, []) if n.get('country') in failed_countries}
    failures_path = directory / 'deep_failures.json'
    failures = read(failures_path, {})
    removed_nodes, removed_keys = set(), []
    for key, record in list(failures.items()):
        scope, separator, node_id = key.partition(':')
        if not separator:
            node_id = key
        if node_id in affected_nodes and (not separator or scope in changed_ids) and transport_failure(record):
            removed_nodes.add(node_id)
            removed_keys.append(key)
            failures.pop(key)
    # Old global cooldowns inherited the same transport failures; preserve successes.
    histories = [state.get('node_history', {})]
    histories.extend(h for cid, h in state.get('channel_node_history', {}).items() if cid in changed_ids)
    for history in histories:
        for nid in removed_nodes:
            if nid in history:
                history[nid].update(cooldown_until=0, consecutive_failures=0)
    result_path = Path('/etc/x-ui/multi-exit-result.json')
    result = read(result_path, {})
    by_id = {c['id']: c for c in config['channels']}
    for item in result.get('channels', []):
        if item.get('id') in by_id:
            item['proxy_address'] = channel_network(channel_slot(by_id[item['id']]))[2]
    report = {'apply': args.apply, 'channels': [{'id': c['id'], 'port': c['inbound_port'], 'network_slot': c['network_slot'], 'proxy_address': channel_network(c['network_slot'])[2]} for c in config['channels']], 'stale_addresses': len(cleanup), 'fixed_outbounds': changed_tags, 'cleared_transport_failures': len(removed_keys)}
    if args.apply:
        write(config_path, config)
        db.execute("update settings set value=? where key='xrayTemplateConfig'", (json.dumps(template, ensure_ascii=False),))
        db.commit()
        for command in cleanup:
            subprocess.run(command, check=True, timeout=10, capture_output=True)
        write(failures_path, failures)
        write(state_path, state)
        if result_path.exists():
            write(result_path, result)
    db.close()
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()

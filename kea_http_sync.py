"""Read-only, token-authenticated HTTP export for Kea shared configuration."""
import hashlib
import ipaddress
import json
import os
import re
import urllib.request

SHARED_FIELDS = ('networks', 'enabled', 'subnet', 'pool_start', 'pool_end', 'router', 'dns_servers', 'domain_name', 'valid_lifetime', 'reservations')
TOKEN_FILE = '/etc/router-manager/kea-sync.token'

def read_token():
    try:
        value = open(TOKEN_FILE, encoding='utf-8').read().strip()
        return value if len(value) >= 32 else None
    except OSError:
        return None

def validate_host(host):
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', host) or '..' in host or host.endswith('.'):
        raise ValueError('Enter a primary IPv4 address or hostname without URL or port')
    try:
        ip = ipaddress.ip_address(host)
        if not isinstance(ip, ipaddress.IPv4Address) or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
            raise ValueError('Invalid primary IPv4 address')
    except ValueError as exc:
        if re.fullmatch(r'[0-9.]+', host):
            raise ValueError('Invalid primary IPv4 address') from exc
    return host

def shared_only(config):
    return {key: config[key] for key in SHARED_FIELDS if key in config}

def merge(primary, backup):
    result = dict(backup)
    result.update(shared_only(primary))
    return result

def config_hash(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def verify_payload(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('config'), dict):
        raise ValueError('Invalid primary DHCP configuration response')
    shared = shared_only(payload['config'])
    if config_hash(shared) != payload.get('sha256'):
        raise ValueError('DHCP configuration hash mismatch')

def fetch(host):
    host = validate_host(host)
    token = read_token()
    if not token:
        raise RuntimeError(f'Missing token (at least 32 characters) in {TOKEN_FILE}')
    req = urllib.request.Request('http://' + host + '/api/kea/config/export', headers={'Authorization': 'Bearer ' + token})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise RuntimeError('Redirects are not allowed for DHCP sync')
    with urllib.request.build_opener(NoRedirect).open(req, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError('Primary export failed')
        data = response.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError('DHCP configuration exceeds size limit')
    result = json.loads(data)
    verify_payload(result)
    return result

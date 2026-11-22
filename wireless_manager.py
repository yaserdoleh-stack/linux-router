"""Wireless station/AP configuration using dedicated per-interface systemd units.

Secrets live in root-only files; do not expose them through GET endpoints.
"""
import os
import ipaddress
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path('/etc/router-manager/wireless')
UNIT_DIR = Path('/etc/systemd/system')
IFACE = re.compile(r'^[a-zA-Z0-9_.-]{1,15}$')
NETWORKD_DIR = Path('/etc/systemd/network')


# Common non-DFS AP channels. The adapter and regulatory domain may restrict these.
AP_CHANNELS = {'2.4': (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
               '5': (36, 40, 44, 48, 149, 153, 157, 161, 165),
               '6': (5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229)}

def validate(name, cfg):
    if not IFACE.fullmatch(name) or name.startswith('-'):
        raise ValueError('Invalid wireless interface name')
    enabled = cfg.get('enabled', True)
    if not isinstance(enabled, bool):
        raise ValueError('Enabled must be true or false')
    mode = cfg.get('mode', 'client')
    if mode not in ('client', 'access_point'):
        raise ValueError('Choose Client or Access Point')
    # Station mode scans all supported bands; AP mode chooses a band and channel.
    if mode == 'client':
        band, channel = 'auto', 'auto'
    else:
        band = str(cfg.get('band', '2.4'))
        if band not in AP_CHANNELS:
            raise ValueError('Band must be 2.4, 5 or 6 GHz')
        raw_channel = cfg.get('channel', 'auto')
        if str(raw_channel).lower() in ('auto', '0', ''):
            channel = 'auto'
        else:
            try:
                channel = int(raw_channel)
            except (ValueError, TypeError):
                raise ValueError('Invalid channel')
            if channel not in AP_CHANNELS[band]:
                raise ValueError('Unsupported channel for selected band')
    ssid = cfg.get('ssid', '')
    password = cfg.get('password', '')
    # Allow disabling an unconfigured radio without inventing credentials.
    if enabled:
        if not isinstance(ssid, str) or not 1 <= len(ssid.encode('utf-8')) <= 32 or '\n' in ssid or '\r' in ssid:
            raise ValueError('SSID must be 1–32 UTF-8 bytes')
        if not isinstance(password, str) or not (8 <= len(password) <= 63) or not password.isascii() or '\n' in password:
            raise ValueError('WPA passphrase must be 8–63 ASCII characters')
    if mode == 'access_point' and enabled and band == '6':
        raise ValueError('6 GHz AP requires WPA3-SAE and PMF; not supported by this WPA2 configuration yet')
    bridge = str(cfg.get('bridge', '') or '').strip() if mode == 'client' else ''
    if bridge and (not IFACE.fullmatch(bridge) or bridge.startswith('-')):
        raise ValueError('Invalid bridge name')
    address_mode = str(cfg.get('address_mode', 'dhcp')) if mode == 'client' else 'none'
    if address_mode not in ('dhcp', 'static', 'none'):
        raise ValueError('Address mode must be DHCP, static, or none')
    if bridge:
        # IP configuration belongs on the bridge, never on a bridge member.
        address_mode = 'none'
    address = str(cfg.get('address', '') or '').strip() if address_mode == 'static' else ''
    gateway = str(cfg.get('gateway', '') or '').strip() if address_mode == 'static' else ''
    dns = str(cfg.get('dns', '') or '').strip() if address_mode == 'static' else ''
    if address_mode == 'static':
        try:
            ipaddress.IPv4Interface(address)
            if gateway: ipaddress.IPv4Address(gateway)
            for server in dns.replace(',', ' ').split(): ipaddress.ip_address(server)
        except ValueError as exc:
            raise ValueError('Invalid static IP, gateway, or DNS address') from exc
    return {'enabled': enabled, 'mode': mode, 'band': band, 'ssid': ssid,
            'password': password, 'channel': channel, 'bridge': bridge,
            'address_mode': address_mode, 'address': address,
            'gateway': gateway, 'dns': dns}


def _atomic(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    try:
        tmp.write_text(value, encoding='utf-8')
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _unit(name, mode):
    binary = '/usr/sbin/hostapd' if mode == 'access_point' else '/usr/sbin/wpa_supplicant'
    conf = ROOT / (name + '.conf')
    args = f'-i{name} -c{conf}' if mode == 'client' else str(conf)
    return f'''[Unit]
Description=Router Manager wireless {mode} on {name}
After=systemd-udev-settle.service
Wants=systemd-udev-settle.service

[Service]
Type=simple
ExecStart={binary} {args}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
'''


def _config(name, cfg):
    ssid = cfg['ssid'].encode().hex()
    if cfg['mode'] == 'client':
        return f'ctrl_interface=/run/wpa_supplicant\nnetwork={{\n    ssid={ssid}\n    psk="{cfg["password"]}"\n    key_mgmt=WPA-PSK\n}}\n'
    # hostapd supports hex SSIDs to preserve arbitrary UTF-8 names.
    hw_mode = 'g' if cfg['band'] == '2.4' else 'a'
    channel = 0 if cfg['channel'] == 'auto' else cfg['channel']
    return (f'interface={name}\ndriver=nl80211\nssid2={ssid}\nhw_mode={hw_mode}\nchannel={channel}\n'
            f'wpa=2\nwpa_key_mgmt=WPA-PSK\nwpa_passphrase={cfg["password"]}\nrsn_pairwise=CCMP\n')


def current_config(name):
    """Read the installed wireless config and live interface/service state.

    Never return WPA passphrases, PSKs or raw configuration files to clients.
    """
    if not IFACE.fullmatch(name) or name.startswith('-'):
        raise ValueError('Invalid wireless interface name')
    unit = f'router-manager-wireless-{name}.service'
    conf = ROOT / (name + '.conf')
    result = {'configured': conf.is_file(), 'enabled': False, 'mode': None,
              'ssid': '', 'band': None, 'channel': None,
              'password_configured': False, 'service_status': 'unknown',
              'interface_mode': 'unknown', 'frequency_mhz': None}
    def run(*args):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=5)
            return r.stdout.strip() if r.returncode == 0 else ''
        except (OSError, subprocess.TimeoutExpired):
            return ''
    result['service_status'] = run('systemctl', 'is-active', unit) or 'inactive'
    result['enabled'] = run('systemctl', 'is-enabled', unit) == 'enabled'
    info = run('iw', 'dev', name, 'info')
    m = re.search(r'^\s*type\s+(\S+)', info, re.M)
    if m: result['interface_mode'] = m.group(1)
    m = re.search(r'^\s*channel\s+(\d+)\s+\((\d+)\s+MHz\)', info, re.M)
    if m:
        result['operating_channel'] = int(m.group(1))
        result['frequency_mhz'] = int(m.group(2))
    if conf.is_file():
        # Parse only known keys; never expose the raw file or credentials.
        try:
            content = conf.read_text(encoding='utf-8')
        except OSError:
            content = ''
        if re.search(r'^interface=', content, re.M):
            result['mode'] = 'access_point'
            m = re.search(r'^ssid2=([0-9a-fA-F]+)$', content, re.M)
            if m:
                try: result['ssid'] = bytes.fromhex(m.group(1)).decode('utf-8')
                except (ValueError, UnicodeError): pass
            else:
                m = re.search(r'^ssid=(.*)$', content, re.M)
                if m: result['ssid'] = m.group(1)
            m = re.search(r'^hw_mode=(\w+)', content, re.M)
            result['band'] = '2.4' if m and m.group(1) == 'g' else '5' if m else None
            m = re.search(r'^channel=(\d+)', content, re.M)
            if m: result['channel'] = int(m.group(1)) or 'auto'
            result['password_configured'] = bool(re.search(r'^wpa_passphrase=|^wpa_psk=', content, re.M))
        elif 'network={' in content:
            result['mode'] = 'client'
            m = re.search(r'^\s*ssid=([0-9a-fA-F]+)', content, re.M)
            if m:
                try: result['ssid'] = bytes.fromhex(m.group(1)).decode('utf-8')
                except (ValueError, UnicodeError): pass
            result['band'] = 'auto'
            result['channel'] = 'auto'
            result['password_configured'] = bool(re.search(r'^\s*psk=', content, re.M))
    return result


def _networkd_path(name):
    return NETWORKD_DIR / f'04-router-manager-wireless-{name}.network'


def _networkd_config(name, cfg):
    if cfg['mode'] != 'client' or not cfg['enabled']:
        return None
    lines = ['[Match]', f'Name={name}', '', '[Network]']
    if cfg['bridge']:
        lines.append(f"Bridge={cfg['bridge']}")
        lines.append('LinkLocalAddressing=no')
    elif cfg['address_mode'] == 'dhcp':
        lines.append('DHCP=ipv4')
    elif cfg['address_mode'] == 'static':
        lines.append(f"Address={cfg['address']}")
        if cfg['gateway']: lines.append(f"Gateway={cfg['gateway']}")
        if cfg['dns']: lines.append('DNS=' + ' '.join(cfg['dns'].replace(',', ' ').split()))
    else:
        lines.append('LinkLocalAddressing=no')
    return '\n'.join(lines) + '\n'


def apply(name, cfg, previous=None):
    """Apply validated config. Preserve old files on failure and restore service."""
    cfg = validate(name, cfg)
    binary = 'hostapd' if cfg['mode'] == 'access_point' else 'wpa_supplicant'
    if cfg['enabled'] and not shutil.which(binary):
        raise RuntimeError(f'{binary} is not installed')
    unit = f'router-manager-wireless-{name}.service'
    unit_path = UNIT_DIR / unit
    config_path = ROOT / (name + '.conf')
    old_unit = unit_path.read_bytes() if unit_path.exists() else None
    old_config = config_path.read_bytes() if config_path.exists() else None
    network_path = _networkd_path(name)
    old_network = network_path.read_bytes() if network_path.exists() else None
    try:
        if cfg['enabled'] and cfg['mode'] == 'client' and cfg['bridge']:
            # Ordinary 3-address Wi-Fi stations cannot transparently join a bridge.
            # Require 4-address support before changing networkd configuration.
            result = subprocess.run(['iw', 'dev', name, 'set', '4addr', 'on'],
                                    capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError('Wi-Fi client bridging requires 4-address/WDS support: ' + result.stderr.strip())
        if cfg['enabled']:
            _atomic(config_path, _config(name, cfg))
            _atomic(unit_path, _unit(name, cfg['mode']), 0o644)
        netcfg = _networkd_config(name, cfg)
        if netcfg is None:
            network_path.unlink(missing_ok=True)
        else:
            _atomic(network_path, netcfg, 0o644)
        subprocess.run(['networkctl', 'reload'], check=True, capture_output=True, text=True)
        subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True, text=True)
        if cfg['enabled']:
            subprocess.run(['systemctl', 'enable', '--now', unit], check=True, capture_output=True, text=True)
            subprocess.run(['systemctl', 'reset-failed', unit], check=False, capture_output=True, text=True)
            subprocess.run(['systemctl', 'restart', unit], check=True, capture_output=True, text=True)
            # systemctl restart can return before hostapd fails during radio
            # initialization. Poll briefly to detect immediate failures.
            import time
            time.sleep(1.5)
            state = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True)
            if state.stdout.strip() != 'active':
                journal = subprocess.run(['journalctl', '-u', unit, '-n', '25', '--no-pager', '-o', 'cat'],
                                         capture_output=True, text=True)
                # Do not leak passphrases from service logs to the web UI.
                raise RuntimeError(f'{unit} failed to start. Check: sudo journalctl -u {unit} -n 50 --no-pager')
        else:
            subprocess.run(['systemctl', 'disable', '--now', unit], check=True, capture_output=True, text=True)
        subprocess.run(['networkctl', 'reconfigure', name], check=False, capture_output=True, text=True)
    except Exception as exc:
        if old_config is None: config_path.unlink(missing_ok=True)
        else:
            config_path.write_bytes(old_config)
            os.chmod(config_path, 0o600)
        if old_network is None: network_path.unlink(missing_ok=True)
        else: network_path.write_bytes(old_network)
        subprocess.run(['networkctl', 'reload'], check=False, capture_output=True)
        if old_unit is None: unit_path.unlink(missing_ok=True)
        else: unit_path.write_bytes(old_unit)
        subprocess.run(['systemctl', 'daemon-reload'], check=False, capture_output=True)
        if old_unit is not None:
            subprocess.run(['systemctl', 'restart', unit], check=False, capture_output=True)
        else:
            subprocess.run(['systemctl', 'disable', '--now', unit], check=False, capture_output=True)
        if isinstance(exc, subprocess.CalledProcessError):
            raise RuntimeError(f'Wireless service {unit} failed during {exc.cmd[1] if len(exc.cmd) > 1 else "operation"}. Check: sudo journalctl -u {unit} -n 50 --no-pager') from exc
        raise

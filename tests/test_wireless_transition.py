from unittest.mock import patch
import wireless_manager as wm


def test_ap_to_client_without_bridge_never_enables_wds(tmp_path):
    old_root, old_unit, old_network = wm.ROOT, wm.UNIT_DIR, wm.NETWORKD_DIR
    wm.ROOT, wm.UNIT_DIR, wm.NETWORKD_DIR = tmp_path / 'wifi', tmp_path / 'units', tmp_path / 'network'
    commands = []
    class Result:
        returncode = 0
        stdout = 'active'
        stderr = ''
    def run(args, **kwargs):
        commands.append(args)
        return Result()
    try:
        with patch.object(wm.shutil, 'which', return_value='/usr/sbin/wpa_supplicant'), patch.object(wm.subprocess, 'run', side_effect=run), patch('time.sleep'):
            wm.apply('wlan0', {'mode':'client','ssid':'home','password':'12345678','address_mode':'dhcp'},
                     {'mode':'access_point','bridge':'lan0'})
        assert ['ip','link','set','dev','wlan0','nomaster'] in commands
        assert not any('4addr' in cmd for cmd in commands)
        assert 'DHCP=ipv4' in (wm.NETWORKD_DIR / '04-router-manager-wireless-wlan0.network').read_text()
    finally:
        wm.ROOT, wm.UNIT_DIR, wm.NETWORKD_DIR = old_root, old_unit, old_network

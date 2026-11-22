import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wireless_manager as wm

def test_modes_and_config():
    client = wm.validate('wlan0', {'mode':'client','ssid':'home','password':'12345678'})
    assert 'network={' in wm._config('wlan0', client)
    ap = wm.validate('wlan0', {'mode':'access_point','ssid':'home','password':'12345678','channel':6})
    assert 'wpa=2' in wm._config('wlan0', ap)

def test_reject_invalid():
    for cfg in ({'mode':'access_point','ssid':'x','password':'short'},
                {'mode':'access_point','ssid':'x','password':'12345678','channel':149,'band':'2.4'},
                {'mode':'client','ssid':'x\ny','password':'12345678'}):
        with pytest.raises(ValueError): wm.validate('wlan0', cfg)

def test_disabled_and_bands():
    assert wm.validate('wlan0', {'enabled': False})['enabled'] is False
    ap5 = wm.validate('wlan0', {'mode':'access_point','ssid':'test','password':'12345678','band':'5','channel':36})
    assert 'hw_mode=a' in wm._config('wlan0', ap5)
    with pytest.raises(ValueError, match='WPA3'):
        wm.validate('wlan0', {'mode':'access_point','ssid':'test','password':'12345678','band':'6','channel':5})
    assert wm.validate('wlan0', {'mode':'client','ssid':'test','password':'12345678','band':'6','channel':5})['band'] == 'auto'


def test_client_auto_and_ap_acs():
    client = wm.validate('wlan0', {'mode':'client','ssid':'home','password':'12345678','band':'6','channel':5})
    assert client['band'] == 'auto' and client['channel'] == 'auto'
    assert 'freq_list=' not in wm._config('wlan0', client)
    for band in ('2.4', '5'):
        ap = wm.validate('wlan0', {'mode':'access_point','ssid':'home','password':'12345678','band':band,'channel':'auto'})
        assert 'channel=0\n' in wm._config('wlan0', ap)

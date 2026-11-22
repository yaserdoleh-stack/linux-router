import pytest
import wireless_manager as wm


def test_client_dhcp():
    cfg = wm.validate('wlan0', {'mode': 'client', 'ssid': 'home', 'password': '12345678'})
    assert 'DHCP=ipv4' in wm._networkd_config('wlan0', cfg)


def test_client_static():
    cfg = wm.validate('wlan0', {'mode': 'client', 'ssid': 'home', 'password': '12345678',
                               'address_mode': 'static', 'address': '192.168.5.2/24',
                               'gateway': '192.168.5.1', 'dns': '1.1.1.1 8.8.8.8'})
    conf = wm._networkd_config('wlan0', cfg)
    assert 'Address=192.168.5.2/24' in conf and 'Gateway=192.168.5.1' in conf


def test_client_bridge_no_ip():
    cfg = wm.validate('wlan0', {'mode': 'client', 'ssid': 'home', 'password': '12345678',
                               'bridge': 'lan0', 'address_mode': 'dhcp'})
    conf = wm._networkd_config('wlan0', cfg)
    assert 'Bridge=lan0' in conf and 'DHCP=' not in conf


def test_bad_static_ip():
    with pytest.raises(ValueError):
        wm.validate('wlan0', {'mode': 'client', 'ssid': 'home', 'password': '12345678',
                              'address_mode': 'static', 'address': 'invalid'})

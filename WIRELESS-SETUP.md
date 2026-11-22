# Wireless client and access point modes

Under **Wireless**, edit a detected Wi-Fi interface and choose **Client** (join an existing Wi-Fi network) or **Access Point** (broadcast a Wi-Fi network). Configure SSID and WPA2-Personal passphrase. For access points, choose a 2.4 GHz channel (1–11). Save to stage changes, then use **Apply Changes**.

Ubuntu/Debian dependencies:

```bash
sudo apt install wpasupplicant hostapd iw
```

The wireless adapter and driver must support the selected role (`iw list` shows supported interface modes). The application creates a dedicated `router-manager-wireless-<interface>.service` and a root-only `/etc/router-manager/wireless/<interface>.conf` file. Credentials are stored in root-only `/var/lib/router-manager/config.json` as part of the staged/applied configuration; protect backups of this file.

**Important:** Disable any existing NetworkManager, iwd, standalone wpa_supplicant, or hostapd configuration managing the same wireless interface before applying. Competing services will prevent reliable operation. Changing the Wi-Fi role can disconnect remote administration. Use a wired or local-console management connection when applying changes.

The wireless mode configures radio association only. IP address configuration remains managed separately through systemd-networkd. Access point mode does not automatically configure DHCP, NAT, bridge membership, or firewall rules; configure these in their respective Router Manager pages. The interface can be enabled or disabled. Access Point mode supports common non-DFS 2.4 GHz and 5 GHz channels (subject to regulatory domain and radio capabilities). 6 GHz can be selected for client configuration, but 6 GHz Access Point mode is deliberately blocked until WPA3-SAE and protected management frames are implemented. The client mode uses WPA2-Personal; 6 GHz client association may require WPA3 and therefore may not work.

The app has not been tested with actual wireless hardware. Validate your interface's capabilities and test in a lab before production deployment.
\n\nClient mode automatically scans available bands; there is no frequency selection. AP mode supports Auto channel (hostapd channel=0, ACS), requiring a hostapd build with ACS support and compatible hardware. 6 GHz AP remains unsupported.\n

## Troubleshooting an access point that does not start

1. Check `iw list` for `AP` in Supported interface modes and verify supported channels.
2. Run `sudo journalctl -u router-manager-wireless-wlan0.service -n 50 --no-pager` (replace wlan0).
3. If using Auto (ACS), try a supported manual channel such as 1 or 6 on 2.4 GHz. `channel=0` requires ACS support in the hostapd build and driver.
4. Check for conflicting NetworkManager, iwd, wpa_supplicant or hostapd instances and regulatory-domain restrictions.
5. AP radio startup does not automatically configure an IP address, bridge, DHCP pool or firewall forwarding.

Wireless Edit now shows the **last successfully applied** settings. If there are pending changes, the form warns that saving replaces that interface's pending draft. Passwords are never returned to the browser; leaving the password blank preserves the staged or applied password.

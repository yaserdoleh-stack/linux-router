# Router Manager

A web-based management interface for a Linux router, built with **FastAPI** and a lightweight HTML/JavaScript frontend. It provides monitoring and configuration workflows for network interfaces, bridges, VLANs, routing, Kea DHCPv4, and nftables.

> **Project status:** Experimental. Test changes from a local console before using on a production router. This application can modify networking and firewall settings and may interrupt remote access.

## Features

- **Monitoring:** View network interface and system status.
- **Interfaces, bridges, and VLANs:** Inspect existing Linux devices and stage supported network configuration changes. Firewall enablement checkboxes are available on these pages.
- **Routing:** View routes and manage supported static routes using systemd-networkd.
- **DHCPv4:** Configure Kea DHCP server settings, address pool, gateway, lease lifetime, domain, up to three DNS servers, and MAC-based IP address reservations; inspect leases.
- **Firewall:** Inspect nftables chains and rules; configure source NAT (by IPv4 CIDR or incoming interface) and TCP/UDP port forwarding.
- **Configuration management:** Save pending changes, apply or undo them, and download/restore `config.json` backups.
- **System controls:** Reboot and shut down the router from the web interface.

## Requirements

- A Linux distribution using **systemd** and **systemd-networkd** (primarily developed for Ubuntu).
- Python 3 with `fastapi`, `uvicorn`, and `pydantic` available to the service's Python interpreter.
- `iproute2` and `systemctl`.
- `nftables` for firewall, NAT, and port forwarding management.
- Kea DHCPv4 server (`kea-dhcp4-server`) for DHCP features.
- Root privileges for the current service configuration.

Install typical Ubuntu dependencies (package names may differ by release):

```bash
sudo apt update
sudo apt install python3 python3-fastapi python3-uvicorn python3-pydantic \
  iproute2 nftables kea-dhcp4-server
```

If your distribution does not provide the Python packages, install them in an appropriate Python environment and update `ExecStart` in the systemd service accordingly.

## Installation

The included installer deploys the application to `/usr/local/lib/router-manager`, installs the systemd service, enables it at boot, and starts it.

```bash
unzip router-manager-usr-local-port80.zip
cd router-manager-usr-local-port80  # or the directory containing the extracted files
sudo bash install-router-manager-local.sh
```

The installer expects `app.py`, `index.html`, and `router-manager.service` in the **same directory** as the installation script. If the ZIP extracts directly into your current directory, run the script there instead.

Open the web interface at:

```text
http://ROUTER_IP/
```

The application listens on **TCP port 80**, on all IPv4 interfaces (`0.0.0.0`). Ensure that port 80 is not occupied by another service.

### Service management

```bash
sudo systemctl status router-manager
sudo systemctl restart router-manager
sudo systemctl stop router-manager
sudo systemctl enable router-manager
sudo journalctl -u router-manager -f
```

For manual troubleshooting:

```bash
cd /usr/local/lib/router-manager
sudo python3 app.py
```

Stop the systemd service first if it is already using port 80.

## Configuration files

| Path | Purpose |
| --- | --- |
| `/usr/local/lib/router-manager/app.py` | FastAPI backend |
| `/usr/local/lib/router-manager/index.html` | Web UI |
| `/etc/systemd/system/router-manager.service` | systemd startup service |
| `/var/lib/router-manager/config.json` | Applied configuration and pending draft |
| `/etc/systemd/network/` | systemd-networkd configuration |
| `/etc/kea/kea-dhcp4.conf` | Kea DHCPv4 configuration |
| `/etc/nftables.conf` | Main nftables configuration |
| `/etc/nftables.d/router-manager.nft` | Router Manager-generated nftables rules |

At startup, the current implementation imports installed systemd-networkd configuration into `config.json` while retaining other stored settings. This **does not** mean every arbitrary networkd file or nftables rule is fully editable or deletable through the UI. Firewall configuration is primarily managed through Router Manager's own ruleset.

## Making changes

1. Open the relevant management page.
2. Edit the configuration and save the draft.
3. Review pending changes.
4. Click **Apply Changes** to activate them, or **Undo Changes** to discard the draft.

Configuration restore is staged first; it is not applied until **Apply Changes** is pressed. Reboot and shutdown actions execute separately and do not use the draft workflow.

**Caution:** Network changes can disconnect the management session. Back up your current configuration and use local console access for initial testing.

## Security

**Do not expose this application to the public internet.** The current service runs as root and serves unencrypted HTTP on port 80. The project does not provide a hardened authentication and authorization layer for administrative operations.

Recommended precautions:

- Restrict access to a trusted management network using an independent firewall policy.
- Use a VPN or an authenticated HTTPS reverse proxy before allowing access from other networks.
- Do not expose the service on the WAN interface.
- Back up `/etc/systemd/network/`, `/etc/nftables.conf`, `/etc/kea/`, and `/var/lib/router-manager/config.json` before making major changes.
- Keep an out-of-band or local console available when applying network and firewall changes.

## Troubleshooting

**Service does not start:**

```bash
sudo systemctl status router-manager
sudo journalctl -u router-manager -n 100 --no-pager
```

**Port 80 is in use:**

```bash
sudo ss -ltnp '( sport = :80 )'
```

**Firewall apply fails:** Confirm `nft` is installed, inspect the generated configuration, and check syntax without loading rules:

```bash
sudo nft -c -f /etc/nftables.conf
```

**DHCP validation fails:** Check the Kea service account and configuration permissions; the service commonly runs as `_kea` on Ubuntu.

## Limitations

- Designed around systemd-networkd, nftables, and Kea DHCPv4, not NetworkManager, firewalld, or iptables-only setups.
- Some externally provisioned interfaces and advanced nftables constructs are not fully supported for editing/deletion.
- Physical NIC hardware cannot be deleted; only its configuration can be removed or the interface disabled.
- Live deployment, rollback behavior, and compatibility with complex existing rulesets require testing on the target router.

## Contributing

Issues and pull requests are welcome. When reporting a bug, include the Linux distribution/version, relevant service logs, and a **redacted** example configuration. Remove passwords, public IP addresses, and other sensitive details before sharing.

## License

Router Manager is licensed under the **GNU General Public License version 3 or (at your option) any later version** (`GPL-3.0-or-later`). See [LICENSE](LICENSE) for the full GNU GPLv3 text.

You may use, modify, and redistribute this software under the terms of the GNU GPL, provided you comply with its conditions, including applicable source-code and license-notice obligations. This software is provided **without warranty**, as described in the license.

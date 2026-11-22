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
- **Administrator login:** Password-protected UI and API, signed session cookies, and a sign-out action.

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

The installer expects `app.py`, `auth.py`, `setup-admin.py`, `login.html`, `index.html`, and `router-manager.service` in the **same directory** as the installation script. If the ZIP extracts directly into your current directory, run the script there instead.

The installer prompts for an administrator password (minimum 12 characters) on first installation. The login username is `admin`. To change the password and invalidate all active sessions:

```bash
sudo python3 /usr/local/lib/router-manager/setup-admin.py
```

Authentication configuration is stored at `/var/lib/router-manager/auth.json` with restricted permissions. **Do not commit this file to GitHub.**

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
| `/var/lib/router-manager/auth.json` | Administrator password hash and signing secret (private) |
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

**Do not expose this application to the public internet.** Login authentication is now required for the UI and API, but the service still runs as root and uses **unencrypted HTTP on port 80**. Passwords and session cookies are not protected against interception on the network. Use HTTPS through a reverse proxy or a VPN, and restrict access to a trusted management network.

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

### DHCP lease alias hostnames

The Active DHCP Leases table provides an editable **Alias hostname** field for each
active Kea lease. Enter a hostname and click **Save**; clear it and click **Save**
to remove the alias. Aliases are stored immediately in
`/var/lib/router-manager/config.json` as `dhcp_lease_aliases`, a mapping from
normalized MAC addresses to alias hostnames. They survive lease expiration,
reassignment, application restarts, and applying other staged changes.
This is display-only metadata; it does not alter Kea reservations, client-supplied
hostnames, or DNS records. Only active leases appear in the table.

DHCP lease aliases accept arbitrary Unicode characters, punctuation and whitespace. Aliases are stored exactly as entered (an empty string removes the alias). They are display labels, not DNS hostnames.

### Kea memfile lease visibility

The DHCP Active Leases view now reads `/var/lib/kea/kea-leases4.csv.2`
(the LFC snapshot) followed by `/var/lib/kea/kea-leases4.csv` (the active
journal). Rows are reconciled by IPv4 address; newer rows override older
records, including expired and non-active records. Only unexpired leases in
state 0 are displayed. This is read-only and does not change Kea's lease
database or restart the DHCP service. The implementation is tailored to the
observed `.2` + primary-file layout; for other LFC intermediate states,
a Kea lease-query API is preferable for a fully authoritative view.

### Dashboard LAN Clients count

The LAN Clients card counts distinct MAC addresses (falling back to IP if no MAC) from the combined Neighbors data: lan0 ARP entries plus active Kea DHCP leases. A device appearing in both sources is counted once. DHCP-only leases whose interface cannot be inferred are included.

### Interface firewall behavior (strict ingress)

When an interface firewall checkbox is enabled and **Apply Changes** is used,
Router Manager creates nftables `inet` **input** and **forward** base chains
with `policy drop`. Traffic **entering** on a selected protected interface
is allowed only when conntrack state is `established` or `related`. Traffic
entering on other interfaces is explicitly accepted by these managed chains.
Disabling all interface checkboxes restores `policy accept` in these chains.

**WARNING:** New connections to the router (including its web UI and SSH),
new forwarded traffic, and DHCP requests arriving on a protected interface
will be blocked. NAT and port-forward entries do **not** override this rule.
Do not protect a management or LAN interface until explicit allow rules are
available. Apply only from a local console or with independent recovery access.
Other nftables base chains can still independently drop traffic; an `accept`
verdict in one base chain does not override drops in another.

## Floating IPs for router clusters (VRRP)

The **Network → Floating IPs** page manages VRRP virtual IP addresses on any
existing Ethernet interface, bridge or VLAN. Requires `keepalived` installed on
both cluster routers (`sudo apt install keepalived`). The installer adds a
**separate** `router-manager-vrrp.service` and does not replace the system's
existing keepalived service. Do not run a second keepalived daemon controlling
identical VRIDs/VIPs; disable the conflicting service manually if applicable.

On both nodes enter the **same floating IP/CIDR, interface and VRID** and use
different priorities (e.g. 150 primary, 100 secondary). Configure local unicast
source and remote peer addresses on each node if multicast VRRP is not allowed.
The VIP must not be configured as a static address in systemd-networkd. VRRP
protocol 112 must be allowed between routers by nftables; otherwise both nodes
may become MASTER. IPv4 VRRP requires layer-2 adjacency; floating IPs are not
synchronized between different broadcast domains. Avoid using the same VRID
for multiple independent instances on the same interface.

Click **Apply VRRP** to validate and activate immediately; this is independent
of the general networkd Apply. Configuration persists in
`/var/lib/router-manager/config.json`, and generated keepalived configuration
is written to `/etc/keepalived/router-manager-vrrp.conf`. The dedicated service
is enabled after a successful nonempty configuration. The UI's VIP presence
status is an address observation, not an authoritative VRRP state report.

**Important:** VRRP only moves an IP address. It does not synchronize DHCP
leases, firewall connection tracking, NAT state, routes, or application data.
Test failover and failback on a nonproduction network before relying on it.

### Optional Kea DHCP HA (experimental)

In DHCP > Kea Configuration, select **Enable High Availability** to use Kea
hot-standby HA. Default is **off**; standalone DHCP is unchanged. Select
Primary on one router and Backup on the other; enter the **other** router's
permanent IPv4 address. The local endpoint is discovered from the selected
DHCP listening interface; floating VRRP IPs in Router Manager are excluded.
The interface must have exactly one eligible permanent IPv4 address.

Requires Kea HA and lease-commands hook libraries (`libdhcp_ha.so` and
`libdhcp_lease_cmds.so`). Both nodes must have the same subnet, pool,
reservations, and lease settings. Kea HA exchanges control traffic over
HTTP TCP/8000 bound to each router's permanent address. **Restrict inbound
TCP/8000 to the peer router in nftables before enabling HA; the generated
control socket does not configure authentication or TLS.** Do not expose it
on WAN or an untrusted LAN. Permit peer traffic in both directions. Check
Kea logs and HA state before relying on failover. The feature is not tested
against a live Kea installation and may require changes for your Kea version.

The HA endpoint is selected at Apply/startup; changing interface addresses
requires regenerating the Kea configuration. No automatic cross-router
synchronization of DHCP configuration is provided: configure both nodes.

## Optional Kea HA DHCP configuration HTTP pull

See `HTTP-KEA-SYNC.md`. The HA backup pulls shared Kea DHCP settings from the HA primary every 60 seconds by default. Local interface, HA role, HA peer IP and sync settings are preserved. The primary exports only shared DHCP settings via a bearer-token-protected read-only HTTP endpoint. A candidate is validated before activation, with best-effort rollback if service activation fails. Plain HTTP is **not encrypted or tamper-resistant**; use only on an isolated trusted management network, restrict TCP 80 to known peers, and prefer HTTPS if network trust cannot be guaranteed. Never expose this endpoint to the internet.

### Automatic HTTP pull on HA backup

When Kea HA is enabled with Backup role, Router Manager automatically polls the primary permanent IPv4 from the existing HA peer setting every 60 seconds. There is no separate HTTP sync checkbox or address field. Set up the shared bearer token as described in `HTTP-KEA-SYNC.md`. HTTP is plaintext and must be confined to a trusted management network.

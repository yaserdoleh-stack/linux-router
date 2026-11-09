from __future__ import annotations

import asyncio
import subprocess
import ipaddress
import os
import tempfile
import platform
import shutil
import socket
import time
import json
import re
import csv
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Body, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from auth import COOKIE, read_auth, verify_password, issue_session, valid_session
from collections import defaultdict, deque
from pydantic import BaseModel, Field

app = FastAPI(title="Linux Router Manager API", version="1.0.0")

# Same-origin only: router administration must not be callable from other websites.
LOGIN_ATTEMPTS = defaultdict(deque)

@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if path not in ('/login', '/api/auth/login'):
        if not valid_session(request.cookies.get(COOKIE, '')):
            if path == '/' or not path.startswith('/api/'):
                return RedirectResponse('/login', status_code=303)
            return JSONResponse({'detail': 'Authentication required'}, status_code=401)
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        origin = request.headers.get('origin')
        referer = request.headers.get('referer')
        host = request.headers.get('host', '')
        if origin and origin not in (f'http://{host}', f'https://{host}'):
            return JSONResponse({'detail': 'Cross-origin requests are forbidden'}, status_code=403)
        if not origin and referer and not (referer.startswith(f'http://{host}/') or referer.startswith(f'https://{host}/')):
            return JSONResponse({'detail': 'Cross-origin requests are forbidden'}, status_code=403)
        if not origin and not referer and path != '/api/auth/login':
            return JSONResponse({'detail': 'Origin or Referer required'}, status_code=403)
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    return response

@app.get('/login', include_in_schema=False)
async def login_page():
    return FileResponse(Path(__file__).parent / 'login.html')

@app.post('/api/auth/login', include_in_schema=False)
async def login(request: Request):
    key = request.client.host if request.client else 'unknown'
    now = time.monotonic()
    attempts = LOGIN_ATTEMPTS[key]
    while attempts and attempts[0] < now - 900:
        attempts.popleft()
    if len(attempts) >= 10:
        return JSONResponse({'detail': 'Too many login attempts'}, status_code=429)
    try:
        payload = await request.json()
        username, password = payload.get('username'), payload.get('password')
    except (ValueError, AttributeError, TypeError):
        return JSONResponse({'detail': 'Invalid request'}, status_code=400)
    if username != 'admin' or not verify_password(password):
        attempts.append(now)
        return JSONResponse({'detail': 'Invalid credentials'}, status_code=401)
    attempts.clear()
    response = JSONResponse({'ok': True})
    response.set_cookie(COOKIE, issue_session(), max_age=28800, httponly=True,
                        samesite='strict', secure=request.url.scheme == 'https', path='/')
    return response

@app.post('/api/auth/logout', include_in_schema=False)
async def logout():
    response = JSONResponse({'ok': True})
    response.delete_cookie(COOKIE, path='/')
    return response


class InterfaceUpdate(BaseModel):
    address: str | None = None
    mtu: int | None = None
    state: str | None = None


class InterfaceCreate(BaseModel):
    name: str
    kind: str = "dummy"
    mtu: int | None = None


class BridgeCreate(BaseModel):
    name: str
    stp: bool = False
    members: list[str] = []
    address_mode: str = "static"
    address: str | None = None


class BridgeUpdate(BaseModel):
    stp: bool | None = None
    members: list[str] | None = None
    address_mode: str | None = None
    address: str | None = None


class VlanCreate(BaseModel):
    name: str
    parent: str
    vlan_id: int
    mtu: int | None = None
    address_mode: str = "static"
    address: str | None = None


class VlanUpdate(BaseModel):
    mtu: int | None = None
    state: str | None = None
    address_mode: str | None = None
    address: str | None = None


class StaticRoute(BaseModel):
    destination: str
    gateway: str | None = None
    dev: str | None = None
    metric: int = 100


class RouteDelete(BaseModel):
    destination: str
    gateway: str | None = None
    dev: str | None = None
    metric: int = 100


class FirewallConfig(BaseModel):
    interfaces: list[str] = Field(default_factory=list)
    nat: list[dict] = Field(default_factory=list)
    pat: list[dict] = Field(default_factory=list)


class KeaReservation(BaseModel):
    ip_address: str
    hw_address: str
    hostname: str | None = None


class KeaDhcpConfig(BaseModel):
    enabled: bool = True
    interface: str = "lan0"
    subnet: str
    pool_start: str
    pool_end: str
    router: str
    dns_servers: list[str] = Field(default_factory=list)
    domain_name: str | None = None
    valid_lifetime: int = 86400
    reservations: list[KeaReservation] = Field(default_factory=list)


NETWORKD_DIR = Path("/etc/systemd/network")
NETWORKD_PREFIX = "05-router-manager-"
NETWORKD_BACKUP_DIR = NETWORKD_DIR / ".router-manager-backups"
NETWORKD_STAGING_DIR = Path("/var/lib/router-manager/.workspace")  # temporary workspace only
NETWORKD_STAGING_MARKER = NETWORKD_STAGING_DIR / ".initialized"
PENDING_CONFIG_JSON = Path("/var/lib/router-manager/pending-config.json")
APPLIED_CONFIG_JSON = Path("/var/lib/router-manager/config.json")
KEA_CONFIG_DIR = Path("/etc/kea")
KEA_DHCP4_CONFIG = KEA_CONFIG_DIR / "kea-dhcp4.conf"
KEA_BACKUP_DIR = KEA_CONFIG_DIR / ".router-manager-backups"
KEA_LEASES_FILE = Path("/var/lib/kea/kea-leases4.csv")
NFT_MANAGED_FILE = Path("/etc/nftables.d/router-manager.nft")
NFT_MAIN_FILE = Path("/etc/nftables.conf")
NFT_INCLUDE_LINE = 'include "/etc/nftables.d/router-manager.nft"'



@app.middleware("http")
async def persist_pending_json_after_mutation(request, call_next):
    response = await call_next(request)
    if (
        request.method in {"POST", "PUT", "DELETE"}
        and request.url.path not in {"/api/config/apply", "/api/config/discard"}
        and response.status_code < 400
        and NETWORKD_STAGING_MARKER.exists()
    ):
        try:
            persist_staging_json()
        except Exception:
            # Do not hide the endpoint response; the next status/apply request
            # will surface a staging persistence error if the JSON file is absent.
            pass
    return response


def validate_ifname(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", name or ""):
        raise HTTPException(400, "Invalid interface name")
    return name


def validate_ipv4_config(address_mode: str, address: str | None) -> tuple[str, str | None]:
    mode = (address_mode or "dhcp").lower()
    if mode not in {"dhcp", "static"}:
        raise HTTPException(400, "Address mode must be DHCP or static")
    if mode == "static":
        if not address:
            raise HTTPException(400, "A static IPv4 address with CIDR is required")
        try:
            parsed = ipaddress.ip_interface(address)
        except ValueError as exc:
            raise HTTPException(400, "Invalid IP address/CIDR") from exc
        if parsed.version != 4:
            raise HTTPException(400, "Use an IPv4 address with CIDR")
        return mode, str(parsed)
    return mode, None


def ensure_networkd_dir(base_dir: Path = NETWORKD_DIR) -> None:
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise HTTPException(500, f"Cannot create {base_dir}: {exc}") from exc


def _write_pending_config_json(files: dict[str, str], route_config: dict | None = None, kea_dhcp: dict | None = None) -> None:
    """Save unapplied edits under config.json.pending without changing live services."""
    APPLIED_CONFIG_JSON.parent.mkdir(parents=True, exist_ok=True)
    if APPLIED_CONFIG_JSON.exists():
        try:
            root = json.loads(APPLIED_CONFIG_JSON.read_text())
            if not isinstance(root, dict) or root.get("version") != 1:
                raise ValueError("Unsupported router-manager config.json format")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(500, f"Cannot stage changes because {APPLIED_CONFIG_JSON} is invalid: {exc}") from exc
    else:
        # Bootstrap the applied baseline before adding a draft so startup
        # reconciliation can never mistake pending edits for applied config.
        root = _bootstrap_applied_config_json()

    pending = root.get("pending") if isinstance(root.get("pending"), dict) else {}
    if not pending and PENDING_CONFIG_JSON.exists():
        # One-time compatibility import from the previous two-file layout.
        try:
            legacy = json.loads(PENDING_CONFIG_JSON.read_text())
            if isinstance(legacy, dict):
                pending.update(legacy)
        except (OSError, json.JSONDecodeError):
            pass
    pending["version"] = 1
    pending["files"] = dict(sorted(files.items()))
    if route_config is not None:
        pending["route_config"] = route_config
    if kea_dhcp is not None:
        pending["kea_dhcp"] = kea_dhcp

    root["pending"] = pending
    tmp = APPLIED_CONFIG_JSON.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(root, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(APPLIED_CONFIG_JSON)
    try:
        PENDING_CONFIG_JSON.unlink()
    except FileNotFoundError:
        pass


def _normalize_firewall(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise HTTPException(400, "Firewall configuration must be an object")
    interfaces = raw.get("interfaces", [])
    if not isinstance(interfaces, list) or len(interfaces) > 32:
        raise HTTPException(400, "Invalid firewall interface list")
    interfaces = list(dict.fromkeys(validate_ifname(x) for x in interfaces))
    nat, pat = [], []
    for item in raw.get("nat", []):
        try:
            outbound = validate_ifname(item["outbound"])
            source_type = item.get("source_type") or ("interface" if item.get("inbound") and not item.get("source") else "cidr")
            if source_type == "cidr":
                source = str(ipaddress.IPv4Network(item["source"], strict=False))
                nat.append({"source_type": "cidr", "source": source, "outbound": outbound})
            elif source_type == "interface":
                inbound = validate_ifname(item["inbound"])
                nat.append({"source_type": "interface", "inbound": inbound, "outbound": outbound})
            else:
                raise ValueError("NAT source type must be cidr or interface")
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(400, f"Invalid NAT rule: {exc}") from exc
    for item in raw.get("pat", []):
        try:
            proto = item["protocol"]
            if proto not in ("tcp", "udp"):
                raise ValueError("Protocol must be TCP or UDP")
            inbound = validate_ifname(item["inbound"])
            external_port = int(item["external_port"])
            internal_port = int(item["internal_port"])
            target = str(ipaddress.IPv4Address(item["target"]))
            if not (1 <= external_port <= 65535 and 1 <= internal_port <= 65535):
                raise ValueError("Ports must be between 1 and 65535")
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(400, f"Invalid PAT rule: {exc}") from exc
        pat.append({"protocol": proto, "inbound": inbound, "external_port": external_port,
                    "target": target, "internal_port": internal_port})
    if len(nat) > 100 or len(pat) > 100:
        raise HTTPException(400, "Too many firewall rules")
    seen = set()
    for item in pat:
        key = (item["inbound"], item["protocol"], item["external_port"])
        if key in seen:
            raise HTTPException(400, "Duplicate PAT port mapping")
        seen.add(key)
    return {"interfaces": interfaces, "nat": nat, "pat": pat}


def _firewall_script(cfg: dict) -> str:
    """Render only Router Manager-owned tables; do not flush unrelated rules."""
    q = json.dumps
    lines = [
        "table inet router_manager_filter {",
        " chain forward { type filter hook forward priority -5; policy accept;",
        "  ct state established,related accept",
        "  ct state invalid drop",
    ]
    # DNAT happens before forward filtering. Accept translated port forwards first.
    for rule in cfg["pat"]:
        lines.append(
            f'  iifname {q(rule["inbound"])} ip daddr {rule["target"]} '
            f'ip protocol {rule["protocol"]} {rule["protocol"]} dport {rule["internal_port"]} '
            f'ct status dnat accept'
        )
    # Protected interfaces drop unsolicited forwarded traffic only.
    for iface in cfg["interfaces"]:
        lines.append(f'  iifname {q(iface)} ct state new drop')
    lines += [" }", "}", "table ip router_manager_nat {",
              " chain prerouting { type nat hook prerouting priority dstnat; policy accept;"]
    for rule in cfg["pat"]:
        lines.append(
            f'  iifname {q(rule["inbound"])} {rule["protocol"]} dport {rule["external_port"]} '
            f'dnat to {rule["target"]}:{rule["internal_port"]}'
        )
    lines += [" }", " chain postrouting { type nat hook postrouting priority srcnat; policy accept;"]
    for rule in cfg["nat"]:
        if rule.get("source_type", "cidr") == "interface":
            lines.append(f'  iifname {q(rule["inbound"])} oifname {q(rule["outbound"])} masquerade')
        else:
            lines.append(f'  ip saddr {rule["source"]} oifname {q(rule["outbound"])} masquerade')
    lines += [" }", "}"]
    return "\n".join(lines) + "\n"


async def _apply_firewall(cfg: dict) -> None:
    """Validate before changing live nftables; persist a dedicated included file."""
    nft = shutil.which("nft")
    if not nft:
        raise HTTPException(503, "nftables is not installed")
    # A fresh installation may not yet have the main nftables configuration.
    # Build it in memory and create it only after all syntax checks succeed.
    if (cfg["nat"] or cfg["pat"]) and Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
        raise HTTPException(409, "IPv4 forwarding is disabled; enable net.ipv4.ip_forward=1 before applying NAT or port forwarding")
    script = _firewall_script(cfg)
    NFT_MANAGED_FILE.parent.mkdir(parents=True, exist_ok=True)
    main_existed = NFT_MAIN_FILE.is_file()
    old_main = NFT_MAIN_FILE.read_text() if main_existed else "#!/usr/sbin/nft -f\n"
    old_managed = NFT_MANAGED_FILE.read_text() if NFT_MANAGED_FILE.exists() else None
    # Check generated syntax independently of the current ruleset.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as test:
        test.write(script)
        test_path = Path(test.name)
    try:
        await run_command(nft, "-c", "-f", str(test_path))
    finally:
        test_path.unlink(missing_ok=True)

    # nftables.conf is the persistent entrypoint. Do not replace existing rules.
    include_present = bool(re.search(r'^\s*include\s+["\']?/etc/nftables\.d/router-manager\.nft["\']?\s*$', old_main, re.M))
    new_main = old_main if include_present else old_main.rstrip() + "\n\n" + NFT_INCLUDE_LINE + "\n"
    # Do not modify /etc/nftables.conf until all validation succeeds.
    # Substitute both quoted include forms with candidate content for validation.
    candidate_main = re.sub(
        r"^\s*include\s+[\"']?/etc/nftables\.d/router-manager\.nft[\"']?\s*$",
        lambda _: script, new_main, flags=re.M,
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False, dir=str(NFT_MAIN_FILE.parent)) as temp:
        temp.write(candidate_main)
        combined_path = Path(temp.name)
    try:
        # Existing include may refer to old managed file; use a temporary file with
        # the candidate substituted rather than checking stale rules.
        await run_command(nft, "-c", "-f", str(combined_path))
    finally:
        combined_path.unlink(missing_ok=True)

    existing = []
    for family, table in (("inet", "router_manager_filter"), ("ip", "router_manager_nat")):
        try:
            await run_command(nft, "list", "table", family, table)
            existing.append((family, table))
        except RuntimeError:
            pass
    batch = "".join(f"delete table {family} {table}\n" for family, table in existing) + script
    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as temp:
        temp.write(batch)
        batch_path = Path(temp.name)
    try:
        await run_command(nft, "-c", "-f", str(batch_path))
        # Apply as a single nft transaction, leaving unrelated tables untouched.
        await run_command(nft, "-f", str(batch_path))
    finally:
        batch_path.unlink(missing_ok=True)

    try:
        # Atomic persistent-file replacement. Save previous content for rollback.
        for target, content in ((NFT_MANAGED_FILE, script), (NFT_MAIN_FILE, new_main)):
            with tempfile.NamedTemporaryFile(mode="w", dir=str(target.parent), delete=False) as temp:
                temp.write(content)
                tmp = Path(temp.name)
            try:
                tmp.chmod(0o644)
                tmp.replace(target)
            finally:
                tmp.unlink(missing_ok=True)
        await run_command("systemctl", "enable", "nftables.service")
    except Exception:
        if main_existed:
            NFT_MAIN_FILE.write_text(old_main)
        else:
            NFT_MAIN_FILE.unlink(missing_ok=True)
        if old_managed is None:
            NFT_MANAGED_FILE.unlink(missing_ok=True)
        else:
            NFT_MANAGED_FILE.write_text(old_managed)
        raise


def _read_pending_config_json() -> dict[str, str] | None:
    payload = _pending_json_payload()
    if not payload.get("files") and not payload.get("route_config") and "kea_dhcp" not in payload:
        return None
    files = payload.get("files", {})
    if not isinstance(files, dict):
        raise HTTPException(500, "Invalid pending files section in config.json")
    clean: dict[str, str] = {}
    for name, content in files.items():
        if not isinstance(name, str) or not name.startswith(NETWORKD_PREFIX):
            raise HTTPException(500, "Invalid managed configuration filename in config.json pending section")
        if Path(name).name != name or not isinstance(content, str):
            raise HTTPException(500, "Invalid configuration entry in config.json pending section")
        clean[name] = content
    return clean


def persist_staging_json() -> None:
    """Sync the temporary editing workspace to the durable JSON staging file."""
    if not NETWORKD_STAGING_MARKER.exists():
        return
    files = {
        path.name: path.read_text()
        for path in NETWORKD_STAGING_DIR.glob(f"{NETWORKD_PREFIX}*")
        if path.is_file()
    }
    _write_pending_config_json(files)


def prepare_staging() -> Path:
    """Materialize the JSON draft into a private workspace for editing.

    The JSON file is the durable pending configuration. Live networkd files are
    untouched until /api/config/apply installs the draft and reloads networkd.
    """
    ensure_networkd_dir()
    ensure_networkd_dir(NETWORKD_STAGING_DIR)
    if not NETWORKD_STAGING_MARKER.exists():
        for old in NETWORKD_STAGING_DIR.glob(f"{NETWORKD_PREFIX}*"):
            if old.is_file():
                old.unlink()
        saved = _read_pending_config_json()
        if saved is None:
            saved = {
                path.name: path.read_text()
                for path in NETWORKD_DIR.glob(f"{NETWORKD_PREFIX}*")
                if path.is_file()
            }
        for name, content in saved.items():
            (NETWORKD_STAGING_DIR / name).write_text(content)
        NETWORKD_STAGING_MARKER.write_text("pending\n")
        persist_staging_json()
    return NETWORKD_STAGING_DIR


def _pending_json_payload() -> dict:
    if APPLIED_CONFIG_JSON.exists():
        try:
            root = json.loads(APPLIED_CONFIG_JSON.read_text())
            pending = root.get("pending") if isinstance(root, dict) else None
            if pending is not None:
                if not isinstance(pending, dict) or pending.get("version") != 1:
                    raise ValueError("Invalid pending section in config.json")
                return pending
        except (OSError, json.JSONDecodeError, ValueError, AttributeError) as exc:
            raise HTTPException(500, f"Cannot read pending config from {APPLIED_CONFIG_JSON}: {exc}") from exc
    # Read the former standalone draft file during upgrade, until the next
    # staging write migrates it into config.json.
    if PENDING_CONFIG_JSON.exists():
        try:
            payload = json.loads(PENDING_CONFIG_JSON.read_text())
            if payload.get("version") != 1:
                raise ValueError("Unsupported pending configuration JSON format")
            return payload
        except (OSError, json.JSONDecodeError, ValueError, AttributeError) as exc:
            raise HTTPException(500, f"Cannot read legacy pending configuration JSON: {exc}") from exc
    return {"version": 1, "files": {}}


def _read_applied_config_json() -> dict | None:
    """Read the last successfully applied router-manager configuration."""
    if not APPLIED_CONFIG_JSON.exists():
        return None
    try:
        payload = json.loads(APPLIED_CONFIG_JSON.read_text())
        if payload.get("version") != 1:
            raise ValueError("Unsupported applied configuration JSON version")
        files = payload.get("files", {})
        routes = payload.get("routes", [])
        if not isinstance(files, dict) or not isinstance(routes, list):
            raise ValueError("Applied configuration JSON has invalid files/routes")

        clean_files: dict[str, str] = {}
        for name, content in files.items():
            if (
                not isinstance(name, str)
                or not name.startswith(NETWORKD_PREFIX)
                or Path(name).name != name
                or not isinstance(content, str)
            ):
                raise ValueError(f"Invalid managed configuration entry: {name!r}")
            clean_files[name] = content

        clean_routes: list[dict] = []
        for route in routes:
            if not isinstance(route, dict):
                raise ValueError("Invalid static route entry")
            clean_routes.append(_validate_static_route(StaticRoute(
                destination=route.get("dst", "default"),
                gateway=route.get("gateway"),
                dev=route.get("dev"),
                metric=int(route.get("metric", 0)),
            )))
        result = {"version": 1, "files": clean_files, "routes": clean_routes}
        if isinstance(payload.get("systemd_networkd"), dict):
            result["systemd_networkd"] = payload["systemd_networkd"]
        if "kea_dhcp" in payload:
            result["kea_dhcp"] = _normalize_kea_dhcp_config(payload["kea_dhcp"])
        if "firewall" in payload:
            result["firewall"] = _normalize_firewall(payload["firewall"])
        return result
    except (OSError, json.JSONDecodeError, ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError(f"Cannot read applied router-manager JSON {APPLIED_CONFIG_JSON}: {exc}") from exc


def _read_installed_networkd_snapshot() -> dict[str, str]:
    """Read installed networkd configuration, including externally owned files.

    Snapshot files are informational; only Router Manager-prefixed files are
    eligible for managed-file writes/deletes during Apply Changes.
    """
    snapshot = {}
    for path in sorted(NETWORKD_DIR.iterdir()) if NETWORKD_DIR.exists() else []:
        if path.is_file() and path.suffix in {".network", ".netdev", ".link"}:
            if path.is_symlink():
                continue
            snapshot[path.name] = path.read_text(encoding="utf-8")
    return snapshot


def refresh_config_json_from_networkd() -> dict:
    """At startup, capture the disk state without applying or losing pending edits."""
    existing = {}
    if APPLIED_CONFIG_JSON.exists():
        existing = json.loads(APPLIED_CONFIG_JSON.read_text(encoding="utf-8"))
        if not isinstance(existing, dict) or existing.get("version") != 1:
            raise RuntimeError("Unsupported config.json format; refusing to overwrite it")

    snapshot = _read_installed_networkd_snapshot()
    managed = {name: content for name, content in snapshot.items()
               if name.startswith(NETWORKD_PREFIX) and name.endswith((".network", ".netdev"))}
    # Keep pending exactly as-is; it is never imported as applied configuration.
    updated = dict(existing)
    updated["version"] = 1
    updated["files"] = managed
    updated["systemd_networkd"] = snapshot
    updated["routes"] = _extract_managed_static_routes_from_networkd()
    APPLIED_CONFIG_JSON.parent.mkdir(parents=True, exist_ok=True)
    tmp = APPLIED_CONFIG_JSON.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
        import os
        os.chmod(tmp, 0o600)
        tmp.replace(APPLIED_CONFIG_JSON)
    finally:
        tmp.unlink(missing_ok=True)
    return updated


def _write_applied_config_json(routes: list[dict], kea_dhcp: dict | None = None) -> None:
    """Commit networkd, routes and optional Kea DHCP config as applied state."""
    files = {
        path.name: path.read_text()
        for path in sorted(NETWORKD_DIR.glob(f"{NETWORKD_PREFIX}*"))
        if path.is_file() and path.suffix in {".network", ".netdev"}
    }
    normalized_routes = []
    for route in routes:
        normalized_routes.append({
            "dst": route.get("dst", "default"),
            "gateway": route.get("gateway"),
            "dev": route.get("dev"),
            "metric": int(route.get("metric", 0)),
        })
    payload: dict[str, Any] = {"version": 1, "files": dict(sorted(files.items())), "routes": normalized_routes}
    if kea_dhcp is not None:
        payload["kea_dhcp"] = _normalize_kea_dhcp_config(kea_dhcp)
    prior = _read_applied_config_json()
    payload["systemd_networkd"] = _read_installed_networkd_snapshot()
    if prior and "firewall" in prior:
        payload["firewall"] = prior["firewall"]
    APPLIED_CONFIG_JSON.parent.mkdir(parents=True, exist_ok=True)
    tmp = APPLIED_CONFIG_JSON.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(APPLIED_CONFIG_JSON)


def _extract_managed_static_routes_from_networkd() -> list[dict]:
    """Import route entries previously written inside Router Manager marker blocks."""
    found: dict[tuple, dict] = {}
    for path in sorted(NETWORKD_DIR.glob("*.network")):
        if not path.is_file():
            continue
        content = path.read_text()
        devices = _networkd_names_from_content(content)
        if not devices and path.name.startswith(f"{NETWORKD_PREFIX}routes-"):
            devices = {path.stem.removeprefix(f"{NETWORKD_PREFIX}routes-")}
        if len(devices) != 1:
            continue
        dev = next(iter(devices))
        inside = False
        in_route = False
        values: dict[str, str] = {}

        def save_route() -> None:
            if not values:
                return
            destination = values.get("Destination", "default")
            if destination == "0.0.0.0/0":
                destination = "default"
            try:
                route = _validate_static_route(StaticRoute(
                    destination=destination,
                    gateway=values.get("Gateway"),
                    dev=dev,
                    metric=int(values.get("Metric", 0)),
                ))
            except (HTTPException, ValueError, TypeError):
                return
            found[_route_key(route)] = route

        for raw in content.splitlines():
            line = raw.strip()
            if line == ROUTE_MARKER_BEGIN:
                inside = True
                in_route = False
                values = {}
                continue
            if line == ROUTE_MARKER_END:
                if inside and in_route:
                    save_route()
                inside = False
                in_route = False
                values = {}
                continue
            if not inside:
                continue
            if line.startswith("[") and line.endswith("]"):
                if in_route:
                    save_route()
                in_route = line.lower() == "[route]"
                values = {}
                continue
            if in_route and "=" in line:
                key, value = (part.strip() for part in line.split("=", 1))
                if key in {"Destination", "Gateway", "Metric"}:
                    values[key] = value
    return list(found.values())


def _bootstrap_applied_config_json() -> dict:
    """One-time migration: treat current managed networkd files as applied state."""
    files = {
        path.name: path.read_text()
        for path in sorted(NETWORKD_DIR.glob(f"{NETWORKD_PREFIX}*"))
        if path.is_file() and path.suffix in {".network", ".netdev"}
    }
    routes = _extract_managed_static_routes_from_networkd()

    # Migrate the older standalone-service JSON if it exists, before that
    # legacy service and file are retired. Marker-derived routes take priority.
    legacy_routes_file = Path("/var/lib/router-manager/static-routes.json")
    if legacy_routes_file.exists():
        try:
            old_payload = json.loads(legacy_routes_file.read_text())
            for raw in old_payload.get("routes", []):
                route = _validate_static_route(StaticRoute(
                    destination=raw.get("dst", "default"),
                    gateway=raw.get("gateway"),
                    dev=raw.get("dev"),
                    metric=int(raw.get("metric", 0)),
                ))
                routes_by_key = {_route_key(item): item for item in routes}
                routes_by_key[_route_key(route)] = route
                routes = list(routes_by_key.values())
        except Exception as exc:
            raise RuntimeError(f"Cannot migrate legacy static routes from {legacy_routes_file}: {exc}") from exc

    _write_applied_config_json(routes)
    return {"version": 1, "files": files, "routes": routes}


def _networkd_names_from_content(content: str) -> set[str]:
    """Return exact interface names from [Match] Name= entries in a network file."""
    names: set[str] = set()
    in_match = False
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_match = line.lower() == "[match]"
            continue
        if in_match and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            if key.lower() == "name":
                for candidate in value.split():
                    if re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", candidate):
                        names.add(candidate)
    return names


def _networkd_names_from_netdev(content: str) -> set[str]:
    names: set[str] = set()
    in_netdev = False
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_netdev = line.lower() == "[netdev]"
        elif in_netdev and line.lower().startswith("name="):
            name = line.split("=", 1)[1].strip()
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", name):
                names.add(name)
    return names


def _sync_managed_networkd_files(files: dict[str, str]) -> set[str]:
    """Make 05-router-manager-* files exactly match the applied JSON snapshot."""
    ensure_networkd_dir()
    desired = dict(files)
    current = {
        path.name: path for path in NETWORKD_DIR.glob(f"{NETWORKD_PREFIX}*")
        if path.is_file() and path.suffix in {".network", ".netdev"}
    }
    affected: set[str] = set()

    for name, path in current.items():
        if name in desired:
            continue
        content = path.read_text()
        affected.update(_networkd_names_from_content(content))
        affected.update(_networkd_names_from_netdev(content))
        _backup_networkd_file(path)
        path.unlink()

    for name, content in desired.items():
        target = NETWORKD_DIR / name
        if target.exists() and target.read_text() == content:
            continue
        if target.exists():
            old = target.read_text()
            affected.update(_networkd_names_from_content(old))
            affected.update(_networkd_names_from_netdev(old))
        affected.update(_networkd_names_from_content(content))
        affected.update(_networkd_names_from_netdev(content))
        _backup_networkd_file(target)
        _write_networkd_atomic(target, content)
    return affected


async def sync_networkd_from_applied_json() -> list[str]:
    """Reconcile live systemd-networkd files with the last applied JSON config."""
    payload = _read_applied_config_json()
    if payload is None:
        # Preserve the currently installed managed configuration on the first
        # run, then use the generated JSON as the source of truth thereafter.
        payload = _bootstrap_applied_config_json()

    affected = _sync_managed_networkd_files(payload["files"])
    # Route blocks are managed independently so they can be merged into an
    # existing administrator-owned .network file without replacing its contents.
    affected.update(_apply_static_routes_to_networkd(payload["routes"]))
    await _remove_legacy_route_service()
    if affected:
        await networkd_reload(*sorted(affected))
    # Older config.json snapshots without this field leave any existing Kea
    # installation untouched. Once the DHCP page is applied, this becomes
    # the authoritative boot-time state for Kea DHCPv4.
    if "kea_dhcp" in payload:
        await _sync_kea_dhcp_from_applied_json(payload["kea_dhcp"])
    return sorted(affected)


def _route_key(route: dict) -> tuple:
    return (route.get("dst", "default"), route.get("gateway") or "", route.get("dev") or "", int(route.get("metric", 0)))


ROUTE_MARKER_BEGIN = "# BEGIN ROUTER-MANAGER STATIC ROUTES"
ROUTE_MARKER_END = "# END ROUTER-MANAGER STATIC ROUTES"


def _strip_managed_route_block(content: str) -> tuple[str, bool]:
    lines = content.splitlines()
    output: list[str] = []
    inside = False
    removed = False
    for line in lines:
        if line.strip() == ROUTE_MARKER_BEGIN:
            inside = True
            removed = True
            continue
        if line.strip() == ROUTE_MARKER_END and inside:
            inside = False
            continue
        if not inside:
            output.append(line)
    if inside:
        raise HTTPException(500, "Unterminated Router Manager route block in systemd-networkd file")
    return "\n".join(output).rstrip() + ("\n" if output else ""), removed


def _network_file_matches_interface(path: Path, interface: str) -> bool:
    import fnmatch
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return False
    in_match = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_match = stripped.lower() == "[match]"
        elif in_match and "=" in stripped:
            key, value = (part.strip() for part in stripped.split("=", 1))
            if key.lower() == "name" and any(fnmatch.fnmatchcase(interface, pattern) for pattern in value.split()):
                return True
    return False


def _backup_networkd_file(path: Path) -> None:
    NETWORKD_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup = NETWORKD_BACKUP_DIR / path.name
    if path.exists() and not backup.exists():
        backup.write_bytes(path.read_bytes())


def _write_networkd_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".router-manager-tmp")
    tmp.write_text(content)
    os.chmod(tmp, 0o644)
    tmp.replace(path)


def _apply_static_routes_to_networkd(routes: list[dict]) -> set[str]:
    """Merge managed [Route] sections into matching .network files idempotently."""
    ensure_networkd_dir()
    affected: set[str] = set()
    cleaned_contents: dict[Path, str] = {}
    removed_generated: set[Path] = set()

    # Remove old managed route blocks in memory first. Keep unrelated settings intact.
    for path in sorted(NETWORKD_DIR.glob("*.network")):
        if not path.is_file():
            continue
        original = path.read_text()
        cleaned, changed = _strip_managed_route_block(original)
        if not changed:
            continue
        affected.update(_networkd_names_from_content(original))
        generated_only = (
            path.name.startswith(f"{NETWORKD_PREFIX}routes-")
            and cleaned.strip() in {
                "[Match]\nName=" + path.stem.removeprefix(f"{NETWORKD_PREFIX}routes-") + "\n\n[Network]",
                "[Match]\nName=" + path.stem.removeprefix(f"{NETWORKD_PREFIX}routes-") + "\n\n[Network]\n",
            }
        )
        cleaned_contents[path] = cleaned
        if generated_only:
            _backup_networkd_file(path)
            removed_generated.add(path)

    by_device: dict[str, list[dict]] = {}
    for route in routes:
        dev = route.get("dev")
        if not dev:
            raise HTTPException(400, "Persistent systemd-networkd routes require an outgoing interface")
        validate_ifname(dev)
        by_device.setdefault(dev, []).append(route)

    for dev, device_routes in by_device.items():
        affected.add(dev)
        candidates = [
            path for path in sorted(NETWORKD_DIR.glob("*.network"))
            if path.is_file() and path not in removed_generated and _network_file_matches_interface(path, dev)
        ]
        if candidates:
            target = candidates[0]
        else:
            target = NETWORKD_DIR / f"{NETWORKD_PREFIX}routes-{dev}.network"
            if target.exists():
                base = cleaned_contents.get(target, target.read_text())
            else:
                base = f"[Match]\nName={dev}\n\n[Network]\n"
            cleaned_contents[target] = base
            removed_generated.discard(target)

        content = cleaned_contents.get(target, target.read_text() if target.exists() else f"[Match]\nName={dev}\n\n[Network]\n").rstrip()
        block = [ROUTE_MARKER_BEGIN]
        for route in sorted(device_routes, key=lambda item: (item.get("dst", "default"), int(item.get("metric", 0)))):
            destination = "0.0.0.0/0" if route.get("dst", "default") == "default" else route["dst"]
            block.extend(["[Route]", f"Destination={destination}"])
            if route.get("gateway"):
                block.append(f"Gateway={route['gateway']}")
            if int(route.get("metric", 0)):
                block.append(f"Metric={int(route['metric'])}")
        block.append(ROUTE_MARKER_END)
        cleaned_contents[target] = content + ("\n\n" if content else "") + "\n".join(block) + "\n"

    for path in removed_generated:
        if path.exists():
            path.unlink()
        cleaned_contents.pop(path, None)
    for path, content in cleaned_contents.items():
        old = path.read_text() if path.exists() else None
        if old == content:
            continue
        _backup_networkd_file(path)
        _write_networkd_atomic(path, content)
        affected.update(_networkd_names_from_content(content))
    return affected


async def _remove_legacy_route_service() -> None:
    """Remove artifacts from the earlier standalone route-restoration design."""
    service = Path("/etc/systemd/system/router-manager-static-routes.service")
    helper = Path("/usr/local/libexec/router-manager-apply-static-routes")
    old_json = Path("/var/lib/router-manager/static-routes.json")
    if shutil.which("systemctl"):
        try:
            await run_command("systemctl", "disable", "--now", "router-manager-static-routes.service")
        except Exception:
            pass
    for path in (service, helper, old_json):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    if shutil.which("systemctl"):
        await run_command("systemctl", "daemon-reload")

def _route_display(route: dict) -> str:
    return f"{route.get('dst', 'default')} via {route.get('gateway') or '—'} dev {route.get('dev') or '—'}"


def _route_pending_changes() -> list[dict[str, str]]:
    payload = _pending_json_payload()
    cfg = payload.get("route_config") or {}
    original = {_route_key(r): r for r in cfg.get("original", [])}
    desired = {_route_key(r): r for r in cfg.get("desired", [])}
    changes = []
    for key in sorted(set(original) | set(desired)):
        if key not in original:
            changes.append({"action": "added", "file": "config.json pending", "kind": "Static route", "target": _route_display(desired[key])})
        elif key not in desired:
            changes.append({"action": "deleted", "file": "config.json pending", "kind": "Static route", "target": _route_display(original[key])})
    return changes


async def _live_static_routes() -> list[dict]:
    try:
        raw = await run_command("ip", "-j", "route", "show", "proto", "static")
        routes = json.loads(raw)
    except Exception:
        routes = []
    normalized = []
    for r in routes:
        normalized.append({"dst": r.get("dst", "default"), "gateway": r.get("gateway"), "dev": r.get("dev"), "metric": int(r.get("metric", 0))})
    return normalized


def _validate_static_route(route: StaticRoute) -> dict:
    try:
        destination = route.destination.strip().lower()
        if destination != "default":
            network = ipaddress.ip_network(destination, strict=False)
            if network.version != 4:
                raise ValueError("Only IPv4 routes are supported in this tab")
            destination = str(network)
        gateway_ip = ipaddress.ip_address(route.gateway) if route.gateway else None
        if gateway_ip and gateway_ip.version != 4:
            raise ValueError("Only IPv4 gateways are supported in this tab")
        gateway = str(gateway_ip) if gateway_ip else None
    except ValueError as exc:
        raise HTTPException(400, f"Invalid route destination or gateway: {exc}") from exc
    if route.metric < 0 or route.metric > 4294967295:
        raise HTTPException(400, "Metric must be between 0 and 4294967295")
    if not route.dev:
        raise HTTPException(400, "Select an outgoing interface; systemd-networkd routes are attached to a link")
    validate_ifname(route.dev)
    return {"dst": destination, "gateway": gateway, "dev": route.dev, "metric": route.metric}


def _staged_config_changes() -> list[dict[str, str]]:
    """Compare staged networkd files, routes and Kea config to applied state."""
    changes: list[dict[str, str]] = []
    if NETWORKD_STAGING_DIR.exists():
        live = {p.name: p for p in NETWORKD_DIR.glob(f"{NETWORKD_PREFIX}*") if p.is_file()}
        staged = {p.name: p for p in NETWORKD_STAGING_DIR.glob(f"{NETWORKD_PREFIX}*") if p.is_file()}

        def describe(name: str) -> tuple[str, str]:
            base = name[len(NETWORKD_PREFIX):] if name.startswith(NETWORKD_PREFIX) else name
            if base.endswith('.netdev'):
                kind = 'Network device'
            elif base.endswith('.network'):
                kind = 'Network configuration'
            else:
                kind = 'Configuration'
            clean = base.rsplit('.', 1)[0]
            if clean.startswith('parent-'):
                clean = clean[7:] + ' (VLAN parent)'
            elif '-member-' in clean:
                bridge, member = clean.split('-member-', 1)
                clean = f'{bridge} member {member}'
            return kind, clean

        for name in sorted(set(live) | set(staged)):
            if name not in live:
                action = 'added'
            elif name not in staged:
                action = 'deleted'
            elif live[name].read_bytes() != staged[name].read_bytes():
                action = 'modified'
            else:
                continue
            kind, target = describe(name)
            changes.append({'action': action, 'file': name, 'kind': kind, 'target': target})

    changes.extend(_route_pending_changes())
    draft = _pending_json_payload()
    if "kea_dhcp" in draft:
        applied = _read_applied_config_json() or {"version": 1, "files": {}, "routes": []}
        desired_kea = _normalize_kea_dhcp_config(draft["kea_dhcp"])
        applied_kea = applied.get("kea_dhcp")
        if desired_kea != applied_kea:
            action = "added" if applied_kea is None else "modified"
            changes.append({
                "action": action,
                "file": "config.json pending",
                "kind": "Kea DHCPv4",
                "target": f"{desired_kea['interface']} · {'enabled' if desired_kea['enabled'] else 'disabled'} · {desired_kea['subnet'] or 'subnet not set'}",
            })
    if "firewall" in draft:
        applied = _read_applied_config_json() or {}
        if _normalize_firewall(draft["firewall"]) != applied.get("firewall", {"interfaces": [], "nat": [], "pat": []}):
            changes.append({"action": "modified", "file": "config.json pending",
                            "kind": "nftables Firewall", "target": "Interface filtering, NAT and PAT"})
    return changes


def has_pending_config() -> bool:
    return bool(_staged_config_changes())


def discard_staging() -> None:
    if NETWORKD_STAGING_DIR.exists():
        for path in NETWORKD_STAGING_DIR.glob(f"{NETWORKD_PREFIX}*"):
            if path.is_file():
                path.unlink()
        try:
            NETWORKD_STAGING_MARKER.unlink()
        except FileNotFoundError:
            pass
        try:
            NETWORKD_STAGING_DIR.rmdir()
        except OSError:
            pass
    # Remove only the draft section; retain the applied config.json root.
    if APPLIED_CONFIG_JSON.exists():
        try:
            root = json.loads(APPLIED_CONFIG_JSON.read_text())
            if isinstance(root, dict) and "pending" in root:
                root.pop("pending", None)
                tmp = APPLIED_CONFIG_JSON.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(root, indent=2) + "\n")
                os.chmod(tmp, 0o600)
                tmp.replace(APPLIED_CONFIG_JSON)
        except (OSError, json.JSONDecodeError):
            pass
    try:
        PENDING_CONFIG_JSON.unlink()
    except FileNotFoundError:
        pass


def write_staged_file(path: Path, content: str) -> None:
    ensure_networkd_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    os.chmod(tmp, 0o644)
    tmp.replace(path)


def write_networkd_file(path: Path, content: str) -> None:
    ensure_networkd_dir()
    if path.exists() and path.read_text() != content:
        NETWORKD_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup = NETWORKD_BACKUP_DIR / path.name
        if not backup.exists():
            backup.write_text(path.read_text())
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    os.chmod(tmp, 0o644)
    tmp.replace(path)


def remove_networkd_file(path: Path) -> None:
    if path.exists():
        NETWORKD_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup = NETWORKD_BACKUP_DIR / path.name
        if not backup.exists():
            backup.write_text(path.read_text())
        path.unlink()


def remove_staged_file(path: Path) -> None:
    if path.exists():
        path.unlink()


def bridge_netdev_path(name: str, base_dir: Path = NETWORKD_DIR) -> Path:
    return base_dir / f"{NETWORKD_PREFIX}{name}.netdev"


def bridge_network_path(name: str, base_dir: Path = NETWORKD_DIR) -> Path:
    return base_dir / f"{NETWORKD_PREFIX}{name}.network"


def bridge_member_network_path(bridge: str, member: str, base_dir: Path = NETWORKD_DIR) -> Path:
    return base_dir / f"{NETWORKD_PREFIX}{bridge}-member-{member}.network"


def vlan_netdev_path(name: str, base_dir: Path = NETWORKD_DIR) -> Path:
    return base_dir / f"{NETWORKD_PREFIX}{name}.netdev"


def vlan_network_path(name: str, base_dir: Path = NETWORKD_DIR) -> Path:
    return base_dir / f"{NETWORKD_PREFIX}{name}.network"


def vlan_parent_network_path(name: str, base_dir: Path = NETWORKD_DIR) -> Path:
    return base_dir / f"{NETWORKD_PREFIX}parent-{name}.network"

def _networkd_match_name(path: Path, name: str) -> bool:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return False
    in_match = False
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("["):
            in_match = line.lower() == "[match]"
            continue
        if in_match and line.lower().startswith("name="):
            pattern = line.split("=", 1)[1].strip()
            if pattern == name:
                return True
    return False


def find_matching_networkd_file(name: str, base_dir: Path = NETWORKD_DIR) -> Path | None:
    if not base_dir.exists():
        return None
    candidates = sorted(
        p for p in base_dir.glob("*.network")
        if _networkd_match_name(p, name)
    )
    return candidates[0] if candidates else None


def add_vlan_to_parent_networkd(parent: str, vlan: str, base_dir: Path) -> Path:
    path = find_matching_networkd_file(parent, base_dir)
    if path is None:
        path = vlan_parent_network_path(parent, base_dir)
        content = vlan_parent_network_content(parent, vlan)
        write_staged_file(path, content) if base_dir == NETWORKD_STAGING_DIR else write_networkd_file(path, content)
        return path

    content = path.read_text()
    lines = content.splitlines()
    in_network = False
    already = False
    insert_at = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            in_network = stripped.lower() == "[network]"
            if in_network:
                insert_at = idx + 1
            continue
        if in_network and stripped.lower().startswith("vlan=") and stripped.split("=", 1)[1].strip() == vlan:
            already = True
            break
    if not already:
        if insert_at is None:
            if lines and lines[-1].strip():
                lines.append("")
            lines.extend(["[Network]", f"VLAN={vlan}"])
        else:
            lines.insert(insert_at, f"VLAN={vlan}")
        new_content = "\n".join(lines).rstrip() + "\n"
        if base_dir == NETWORKD_STAGING_DIR:
            write_staged_file(path, new_content)
        else:
            write_networkd_file(path, new_content)
    return path


def bridge_netdev_content(name: str, stp: bool) -> str:
    return f"""[NetDev]\nName={name}\nKind=bridge\n\n[Bridge]\nSTP={'yes' if stp else 'no'}\n"""


def ipv4_network_section(address_mode: str, address: str | None) -> str:
    mode, addr = validate_ipv4_config(address_mode, address)
    if mode == "dhcp":
        return "DHCP=ipv4\n"
    return f"Address={addr}\n"


def bridge_network_content(name: str, address_mode: str, address: str | None) -> str:
    return f"""[Match]\nName={name}\n\n[Network]\n{ipv4_network_section(address_mode, address)}"""


def bridge_member_network_content(member: str, bridge: str) -> str:
    return f"""[Match]\nName={member}\n\n[Network]\nBridge={bridge}\n"""


def vlan_netdev_content(name: str, vlan_id: int) -> str:
    return f"""[NetDev]\nName={name}\nKind=vlan\n\n[VLAN]\nId={vlan_id}\n"""


def vlan_network_content(name: str, address_mode: str, address: str | None) -> str:
    return f"""[Match]\nName={name}\n\n[Network]\n{ipv4_network_section(address_mode, address)}"""


def vlan_parent_network_content(parent: str, vlan: str) -> str:
    return f"""[Match]\nName={parent}\n\n[Network]\nVLAN={vlan}\n"""


async def networkd_reload(*interfaces: str) -> None:
    if not shutil.which("networkctl"):
        raise HTTPException(503, "networkctl is not installed")
    await run_command("networkctl", "reload")
    for interface in dict.fromkeys(i for i in interfaces if i):
        try:
            await run_command("networkctl", "reconfigure", interface)
        except RuntimeError:
            # A newly-created netdev may not be visible until networkd settles.
            await asyncio.sleep(0.25)
            await run_command("networkctl", "reconfigure", interface)


async def write_bridge_networkd(name: str, stp: bool, members: list[str], address_mode: str, address: str | None, base_dir: Path = NETWORKD_STAGING_DIR) -> None:
    validate_ifname(name)
    mode, addr = validate_ipv4_config(address_mode, address)
    if base_dir == NETWORKD_STAGING_DIR:
        prepare_staging()
        writer = write_staged_file
    else:
        writer = write_networkd_file
    writer(bridge_netdev_path(name, base_dir), bridge_netdev_content(name, stp))
    writer(bridge_network_path(name, base_dir), bridge_network_content(name, mode, addr))

    desired = set(members)
    existing = base_dir.glob(f"{NETWORKD_PREFIX}{name}-member-*.network")
    for path in existing:
        member = path.name[len(f"{NETWORKD_PREFIX}{name}-member-"):-len(".network")]
        if member not in desired:
            if base_dir == NETWORKD_STAGING_DIR:
                remove_staged_file(path)
            else:
                remove_networkd_file(path)
    for member in desired:
        validate_ifname(member)
        writer(bridge_member_network_path(name, member, base_dir), bridge_member_network_content(member, name))


async def write_vlan_networkd(name: str, parent: str, vlan_id: int, mtu: int | None, address_mode: str, address: str | None, base_dir: Path = NETWORKD_STAGING_DIR, state: str | None = None) -> None:
    validate_ifname(name)
    validate_ifname(parent)
    if not 1 <= vlan_id <= 4094:
        raise HTTPException(400, "VLAN ID must be 1-4094")
    mode, addr = validate_ipv4_config(address_mode, address)
    if base_dir == NETWORKD_STAGING_DIR:
        prepare_staging()
        writer = write_staged_file
    else:
        writer = write_networkd_file
    if state is not None and state not in ("up", "down"):
        raise HTTPException(400, "State must be up or down")
    writer(vlan_netdev_path(name, base_dir), vlan_netdev_content(name, vlan_id))
    writer(vlan_network_path(name, base_dir), vlan_network_content(name, mode, addr))
    if mtu is not None or state in ("up", "down"):
        if mtu is not None and not 576 <= mtu <= 65535:
            raise HTTPException(400, "MTU must be between 576 and 65535")
        path = vlan_network_path(name, base_dir)
        content = path.read_text()
        link_lines = []
        if mtu is not None:
            link_lines.append(f"MTUBytes={mtu}")
        if state in ("up", "down"):
            link_lines.append(f"ActivationPolicy={state}")
        content = content.replace("[Network]\n", "[Link]\n" + "\n".join(link_lines) + "\n\n[Network]\n", 1)
        writer(path, content)
    add_vlan_to_parent_networkd(parent, name, base_dir)


def interface_network_path(name: str, base_dir: Path = NETWORKD_DIR) -> Path:
    return base_dir / f"{NETWORKD_PREFIX}interface-{name}.network"


def interface_network_content(name: str, address_mode: str | None, address: str | None, mtu: int | None, bridge: str | None = None, state: str | None = None) -> str:
    mode = address_mode or "dhcp"
    content = f"[Match]\nName={name}\n\n[Link]\n"
    if mtu is not None:
        content += f"MTUBytes={mtu}\n"
    if state in ("up", "down"):
        content += f"ActivationPolicy={state}\n"
    content += "\n[Network]\n"
    if bridge:
        content += f"Bridge={bridge}\n"
    content += ipv4_network_section(mode, address)
    return content


async def configure_ipv4(interface: str, address_mode: str | None, address: str | None) -> None:
    """Legacy runtime helper. Persistent bridge/VLAN changes use networkd writers above."""
    if address_mode is None:
        return
    mode, addr = validate_ipv4_config(address_mode, address)
    await run_command("ip", "-4", "addr", "flush", "dev", interface)
    if mode == "static":
        await run_command("ip", "-4", "addr", "replace", addr, "dev", interface)
        return
    # networkd owns DHCP; trigger it rather than spawning a competing DHCP client.
    await networkd_reload(interface)


def _default_kea_dhcp_config(interfaces: list[dict] | None = None) -> dict:
    interfaces = interfaces or []
    selected = next((item for item in interfaces if item.get("name") == "lan0"), None)
    address = None
    if selected:
        address = next((value for value in selected.get("addresses", []) if "." in value and "/" in value), None)
    subnet = router = pool_start = pool_end = ""
    if address:
        try:
            ipif = ipaddress.ip_interface(address)
            network = ipif.network
            router = str(ipif.ip)
            subnet = str(network)
            host_count = network.num_addresses - 2
            first_offset = min(100, max(2, host_count - 20))
            last_offset = max(first_offset, min(199, host_count))
            first = int(network.network_address) + first_offset
            last = int(network.network_address) + last_offset
            if int(first) <= int(ipif.ip) <= int(last):
                if int(ipif.ip) < last:
                    first = int(ipif.ip) + 1
                else:
                    last = int(ipif.ip) - 1
            if first <= last:
                pool_start, pool_end = str(ipaddress.ip_address(first)), str(ipaddress.ip_address(last))
        except ValueError:
            pass
    return {
        "enabled": False,
        "interface": "lan0" if selected else (interfaces[0]["name"] if interfaces else "lan0"),
        "subnet": subnet,
        "pool_start": pool_start,
        "pool_end": pool_end,
        "router": router,
        "dns_servers": [router] if router else [],
        "domain_name": None,
        "valid_lifetime": 86400,
        "reservations": [],
    }


def _normalize_kea_dhcp_config(raw: dict) -> dict:
    try:
        config = KeaDhcpConfig(**raw).model_dump()
        interface = validate_ifname(config["interface"])
        if not config["enabled"] and not any((config.get("subnet"), config.get("pool_start"), config.get("pool_end"), config.get("router"))):
            lifetime = int(config.get("valid_lifetime", 86400))
            if lifetime < 300 or lifetime > 604800:
                raise ValueError("Lease time must be between 300 seconds and 7 days")
            return {
                "enabled": False, "interface": interface, "subnet": "",
                "pool_start": "", "pool_end": "", "router": "",
                "dns_servers": [], "domain_name": None, "valid_lifetime": lifetime,
                "reservations": config.get("reservations", []),
            }
        subnet_value = config["subnet"].strip()
        network = ipaddress.ip_network(subnet_value, strict=False)
        if network.version != 4:
            raise ValueError("Only IPv4 subnets are supported")
        if network.prefixlen > 30:
            raise ValueError("DHCP subnet must have at least two usable host addresses")
        start = ipaddress.ip_address(config["pool_start"].strip())
        end = ipaddress.ip_address(config["pool_end"].strip())
        router = ipaddress.ip_address(config["router"].strip())
        if start.version != 4 or end.version != 4 or router.version != 4:
            raise ValueError("Pool and router addresses must be IPv4")
        if start not in network or end not in network or router not in network:
            raise ValueError("Pool and router addresses must be inside the configured subnet")
        if int(start) > int(end):
            raise ValueError("Pool start must be less than or equal to pool end")
        if start in {network.network_address, network.broadcast_address} or end in {network.network_address, network.broadcast_address}:
            raise ValueError("DHCP pool cannot include the subnet or broadcast address")
        if router in {network.network_address, network.broadcast_address}:
            raise ValueError("Router address cannot be the subnet or broadcast address")
        if int(start) <= int(router) <= int(end):
            raise ValueError("DHCP pool must not include the router's own address")
        dns = []
        if len(config.get("dns_servers", [])) > 3:
            raise ValueError("Specify no more than three DHCP DNS servers")
        for item in config.get("dns_servers", []):
            address = ipaddress.ip_address(item.strip())
            if address.version != 4:
                raise ValueError("DNS server addresses must be IPv4")
            if str(address) not in dns:
                dns.append(str(address))
        lifetime = int(config["valid_lifetime"])
        if lifetime < 300 or lifetime > 604800:
            raise ValueError("Lease time must be between 300 seconds and 7 days")
        reservations = []
        seen_ips, seen_macs = set(), set()
        for item in config.get("reservations", []):
            address = ipaddress.ip_address(item["ip_address"].strip())
            if address.version != 4 or address not in network or address in {network.network_address, network.broadcast_address}:
                raise ValueError(f"Reservation address {address} must be a usable IPv4 address inside {network}")
            if address == router:
                raise ValueError("A reservation cannot use the router address")
            if int(start) <= int(address) <= int(end):
                raise ValueError(f"Reservation {address} must be outside the dynamic DHCP pool")
            mac = item["hw_address"].strip().lower().replace("-", ":")
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                raise ValueError(f"Invalid reservation MAC address: {mac}")
            if str(address) in seen_ips or mac in seen_macs:
                raise ValueError("Duplicate reservation IP address or MAC address")
            seen_ips.add(str(address))
            seen_macs.add(mac)
            hostname = (item.get("hostname") or "").strip() or None
            if hostname and (len(hostname) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", hostname)):
                raise ValueError(f"Invalid reservation hostname: {hostname}")
            reservation = {"ip-address": str(address), "hw-address": mac}
            if hostname:
                reservation["hostname"] = hostname
            reservations.append(reservation)
        domain = (config.get("domain_name") or "").strip() or None
        if domain and (len(domain) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*", domain)):
            raise ValueError("Invalid DNS domain name")
        return {
            "enabled": bool(config["enabled"]),
            "interface": interface,
            "subnet": str(network),
            "pool_start": str(start),
            "pool_end": str(end),
            "router": str(router),
            "dns_servers": dns,
            "domain_name": domain,
            "valid_lifetime": lifetime,
            "reservations": [
                {"ip_address": r["ip-address"], "hw_address": r["hw-address"], "hostname": r.get("hostname")}
                for r in reservations
            ],
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, f"Invalid Kea DHCP configuration: {exc}") from exc


def _kea_dhcp4_document(config: dict) -> dict:
    options = [{"name": "routers", "data": config["router"]}]
    if config.get("dns_servers"):
        options.append({"name": "domain-name-servers", "data": ", ".join(config["dns_servers"])})
    if config.get("domain_name"):
        options.append({"name": "domain-name", "data": config["domain_name"]})
    lifetime = int(config["valid_lifetime"])
    return {
        "Dhcp4": {
            "interfaces-config": {"interfaces": [config["interface"]]},
            "lease-database": {
                "type": "memfile",
                "persist": True,
                "name": str(KEA_LEASES_FILE),
            },
            "valid-lifetime": lifetime,
            "renew-timer": max(1, int(lifetime / 2)),
            "rebind-timer": max(2, int(lifetime * 0.875)),
            # Keep the Kea default: not authoritative. A second DHCP server
            # or a different subnet on the segment should not be NAKed by default.
            "authoritative": False,
            "subnet4": [{
                "id": 1,
                "subnet": config["subnet"],
                "pools": [{"pool": f"{config['pool_start']} - {config['pool_end']}"}],
                "reservations": [
                    {"ip-address": r["ip_address"], "hw-address": r["hw_address"],
                     **({"hostname": r["hostname"]} if r.get("hostname") else {})}
                    for r in config.get("reservations", [])
                ],
                "option-data": options,
            }],
        }
    }


async def _find_kea_service_unit() -> str | None:
    if not shutil.which("systemctl"):
        return None
    for unit in ("kea-dhcp4-server.service", "kea-dhcp4.service"):
        try:
            state = (await run_command("systemctl", "show", "-p", "LoadState", "--value", unit)).strip()
            if state and state != "not-found":
                return unit
        except Exception:
            continue
    return None


async def _kea_service_state() -> tuple[str | None, bool, bool]:
    unit = await _find_kea_service_unit()
    if not unit:
        return None, False, False
    try:
        active = (await run_command("systemctl", "is-active", unit)).strip() == "active"
    except Exception:
        active = False
    try:
        enabled = (await run_command("systemctl", "is-enabled", unit)).strip() in {"enabled", "enabled-runtime", "static"}
    except Exception:
        enabled = False
    return unit, active, enabled


def _write_kea_config_for_test(content: str, mode: int = 0o644) -> None:
    """Write a candidate at Kea's canonical config path for AppArmor compatibility.

    Some distro AppArmor profiles allow Kea to read only /etc/kea/kea-dhcp4.conf.
    A randomly named/hidden test file can therefore fail with ENOENT/EACCES even
    though Router Manager successfully created it. Validation is run against the
    canonical path; the previous contents are restored immediately afterwards.
    """
    KEA_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(KEA_DHCP4_CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)


def _restore_kea_config_after_test(original: bytes | None, original_stat: os.stat_result | None) -> None:
    """Restore the original config exactly, or remove the candidate if absent."""
    if original is None:
        try:
            KEA_DHCP4_CONFIG.unlink()
        except FileNotFoundError:
            pass
        return

    tmp = KEA_CONFIG_DIR / "kea-dhcp4.conf.router-manager-restore"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(original)
            handle.flush()
            os.fsync(handle.fileno())
        if original_stat is not None:
            os.fchmod(fd, original_stat.st_mode & 0o7777)
            if os.geteuid() == 0:
                os.fchown(fd, original_stat.st_uid, original_stat.st_gid)
    finally:
        os.close(fd)
    tmp.replace(KEA_DHCP4_CONFIG)


async def _validate_kea_dhcp_install(config: dict) -> tuple[str, Path]:
    if not config.get("enabled"):
        unit = await _find_kea_service_unit()
        return unit or "", Path()
    binary = shutil.which("kea-dhcp4")
    if not binary:
        raise HTTPException(503, "Kea DHCPv4 is not installed (kea-dhcp4 executable not found)")
    unit = await _find_kea_service_unit()
    if not unit:
        raise HTTPException(503, "Kea DHCPv4 systemd service not found; install kea-dhcp4-server first")

    normalized = _normalize_kea_dhcp_config(config)
    candidate = json.dumps(_kea_dhcp4_document(normalized), indent=2) + "\n"
    # Validate the GENERATED candidate, not the existing live configuration.
    # Never replace/truncate the active Kea config during a syntax check.
    KEA_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    test_path = None
    try:
        fd, name = tempfile.mkstemp(prefix="kea-dhcp4.conf.", suffix=".test", dir=KEA_CONFIG_DIR)
        test_path = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(test_path, 0o644)
        process = await asyncio.create_subprocess_exec(
            binary, "-t", str(test_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode:
            diagnostic = (stderr + b"\n" + stdout).decode(errors="replace").strip()
            raise HTTPException(
                400,
                "Generated DHCP configuration failed Kea validation "
                f"(existing {KEA_DHCP4_CONFIG} was not modified): "
                + (diagnostic or f"kea-dhcp4 exited {process.returncode}"),
            )
    except HTTPException:
        raise
    except OSError as exc:
        raise HTTPException(500, f"Unable to create or test Kea candidate configuration: {exc}") from exc
    finally:
        if test_path is not None:
            test_path.unlink(missing_ok=True)
    return unit, Path(binary)


async def _apply_kea_dhcp_config(config: dict) -> None:
    normalized = _normalize_kea_dhcp_config(config)
    unit, _binary = await _validate_kea_dhcp_install(normalized)
    if not normalized["enabled"]:
        if unit:
            try:
                await run_command("systemctl", "disable", "--now", unit)
            except Exception as exc:
                # Treat already-disabled/inactive as success, but surface a
                # failure if systemd still reports the service active.
                _unit, active, enabled = await _kea_service_state()
                if active or enabled:
                    raise HTTPException(500, f"Could not disable Kea DHCP service: {exc}") from exc
        return

    KEA_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    KEA_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if KEA_DHCP4_CONFIG.exists():
        backup = KEA_BACKUP_DIR / KEA_DHCP4_CONFIG.name
        if not backup.exists():
            backup.write_bytes(KEA_DHCP4_CONFIG.read_bytes())
    content = json.dumps(_kea_dhcp4_document(normalized), indent=2) + "\n"
    changed = not KEA_DHCP4_CONFIG.exists() or KEA_DHCP4_CONFIG.read_text() != content
    if changed:
        tmp = KEA_DHCP4_CONFIG.with_name(KEA_DHCP4_CONFIG.name + ".router-manager-tmp")
        tmp.write_text(content)
        os.chmod(tmp, 0o644)
        tmp.replace(KEA_DHCP4_CONFIG)
    service, active, enabled = await _kea_service_state()
    if not enabled:
        await run_command("systemctl", "enable", unit)
    if changed or not active:
        await run_command("systemctl", "restart", unit)


async def _sync_kea_dhcp_from_applied_json(config: dict) -> None:
    """Idempotently restore the last applied Kea DHCP config at app startup."""
    normalized = _normalize_kea_dhcp_config(config)
    await _validate_kea_dhcp_install(normalized)
    await _apply_kea_dhcp_config(normalized)


def _read_kea_leases(config: dict) -> list[dict]:
    if not config or not config.get("enabled") or not KEA_LEASES_FILE.exists():
        return []
    now = int(time.time())
    leases: list[dict] = []
    try:
        with KEA_LEASES_FILE.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                try:
                    expires = int(row.get("expire", "0"))
                    state = int(row.get("state", "0") or 0)
                    if expires <= now or state != 0:
                        continue
                    leases.append({
                        "address": row.get("address", ""),
                        "mac": row.get("hwaddr", ""),
                        "hostname": row.get("hostname", "") or "—",
                        "expires_at": expires,
                        "remaining_seconds": max(0, expires - now),
                    })
                except (TypeError, ValueError):
                    continue
    except OSError:
        return []
    valid_leases = []
    for lease in leases:
        try:
            ipaddress.IPv4Address(lease["address"])
            valid_leases.append(lease)
        except ipaddress.AddressValueError:
            continue
    return sorted(valid_leases, key=lambda item: int(ipaddress.ip_address(item["address"])))


async def run_command(*args: str) -> str:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode:
        raise RuntimeError(stderr.decode().strip() or f"command failed: {' '.join(args)}")
    return stdout.decode()


def read_cpu_percent() -> float:
    # Lightweight approximation from /proc/stat.
    first = Path("/proc/stat").read_text().splitlines()[0].split()
    user, nice, system, idle, iowait, irq, softirq, steal = map(int, first[1:9])
    idle_total = idle + iowait
    total = user + nice + system + idle_total + irq + softirq + steal
    previous = getattr(read_cpu_percent, "_previous", None)
    read_cpu_percent._previous = (total, idle_total)
    if not previous:
        return 0.0
    old_total, old_idle = previous
    total_delta = total - old_total
    idle_delta = idle_total - old_idle
    return round(100 * (1 - idle_delta / total_delta), 1) if total_delta else 0.0


async def get_interfaces() -> list[dict[str, Any]]:
    raw = await run_command("ip", "-j", "-details", "address", "show")
    interfaces = []

    for item in json.loads(raw):
        name = item["ifname"]
        linkinfo = item.get("linkinfo") or {}
        info_kind = (linkinfo.get("info_kind") or "").lower()

        # Kernel/sysfs is more reliable than link_type for distinguishing
        # bridges and VLANs. In particular, Linux bridges such as lan0/wan0
        # commonly report link_type=ether even though they are bridges.
        sysfs = Path("/sys/class/net") / name
        is_bridge = (sysfs / "bridge").is_dir() or info_kind == "bridge"
        is_vlan = info_kind == "vlan" or (Path("/proc/net/vlan") / name).exists()
        is_wireless = (sysfs / "wireless").is_dir()

        if is_bridge:
            category = "bridges"
        elif is_vlan:
            category = "vlans"
        elif is_wireless:
            category = "wireless"
        elif (sysfs / "device").exists() and name != "lo":
            category = "ethernet"
        else:
            category = "other"

        addresses = [
            f"{addr['local']}/{addr['prefixlen']}"
            for addr in item.get("addr_info", [])
            if addr.get("family") in ("inet", "inet6")
        ]

        vlan_id = None
        parent = None
        if is_vlan:
            vlan_data = linkinfo.get("info_data") or {}
            vlan_id = vlan_data.get("id")
            parent = item.get("link")

        interfaces.append({
            "name": name,
            "type": {"ethernet":"Ethernet","wireless":"Wireless","bridges":"Bridge","vlans":"VLAN","other":"Other"}[category],
            "category": category,
            "operstate": item.get("operstate", "unknown").lower(),
            "addresses": addresses,
            "mtu": item.get("mtu"),
            "speed": "—",
            "parent": parent,
            "vlan_id": vlan_id,
            "kind": info_kind or item.get("link_type", "unknown"),
            "managed_by_app": any((
                interface_network_path(name).exists(),
                bridge_netdev_path(name).exists(),
                vlan_netdev_path(name).exists(),
                bridge_network_path(name).exists(),
                vlan_network_path(name).exists(),
            )),
        })
    return interfaces


async def get_bridges() -> list[dict[str, Any]]:
    items = await get_interfaces()
    bridges = []
    for item in items:
        if item.get("category") != "bridges":
            continue
        name = item["name"]
        brif = Path("/sys/class/net") / name / "brif"
        members = sorted(p.name for p in brif.iterdir()) if brif.is_dir() else []
        stp_path = Path("/sys/class/net") / name / "bridge" / "stp_state"
        try:
            stp_enabled = stp_path.read_text().strip() == "1"
        except (FileNotFoundError, OSError):
            stp_enabled = None
        bridges.append({
            **item,
            "members": members,
            "stp_enabled": stp_enabled,
        })
    return bridges


async def get_vlans() -> list[dict[str, Any]]:
    items = await get_interfaces()
    return [item for item in items if item.get("category") == "vlans"]


BASE_DIR = Path(__file__).parent

# Optional: serve static assets from ./static
static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root():
    return FileResponse(BASE_DIR / "index.html")

@app.get("/favicon.ico")
async def favicon():
    favicon = BASE_DIR / "linux.svg"
    if favicon.exists():
        return FileResponse(favicon)
    raise HTTPException(404, "Favicon not found")

@app.get("/api/health")
async def health():
    return {"status": "ok", "hostname": socket.gethostname()}

@app.get("/api/interfaces")
async def interfaces():
    try:
        return await get_interfaces()
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/api/interfaces/{name}")
async def interface_detail(name: str):
    items = await get_interfaces()
    for item in items:
        if item["name"] == name:
            return item
    raise HTTPException(404, "Interface not found")


@app.put("/api/interfaces/{name}")
async def update_interface(name: str, update: InterfaceUpdate):
    items = await get_interfaces()
    current = next((x for x in items if x["name"] == name), None)
    if current is None:
        raise HTTPException(404, "Interface not found")
    try:
        validate_ifname(name)
        mtu = update.mtu if update.mtu is not None else current.get("mtu")
        if mtu is not None and not 576 <= mtu <= 65535:
            raise HTTPException(400, "MTU must be between 576 and 65535")
        if update.state is not None and update.state not in ("up", "down"):
            raise HTTPException(400, "State must be up or down")

        master = None
        master_path = Path("/sys/class/net") / name / "master"
        if master_path.exists():
            try:
                master = master_path.resolve().name
            except OSError:
                master = None

        stage_dir = prepare_staging()
        path = interface_network_path(name, stage_dir)
        live_path = interface_network_path(name)
        existing = path.read_text() if path.exists() else (live_path.read_text() if live_path.exists() else "")
        current_ipv4 = next((a for a in current.get("addresses", []) if ":" not in a), None)
        if update.address:
            mode, address = validate_ipv4_config("static", update.address)
        elif "DHCP=ipv4" in existing:
            mode, address = "dhcp", None
        elif any(line.startswith("Address=") for line in existing.splitlines()):
            mode = "static"
            address = next((line.split("=", 1)[1].strip() for line in existing.splitlines() if line.startswith("Address=")), current_ipv4)
        elif current_ipv4:
            mode, address = "static", current_ipv4
        else:
            mode, address = None, None

        if master:
            path = bridge_member_network_path(master, name, stage_dir)
            content = f"[Match]\nName={name}\n\n[Link]\n"
            if mtu is not None:
                content += f"MTUBytes={mtu}\n"
            if update.state in ("up", "down"):
                content += f"ActivationPolicy={update.state}\n"
            content += f"\n[Network]\nBridge={master}\n"
        else:
            if mode is None:
                content = f"[Match]\nName={name}\n\n[Link]\n"
                if mtu is not None:
                    content += f"MTUBytes={mtu}\n"
                if update.state in ("up", "down"):
                    content += f"ActivationPolicy={update.state}\n"
                content += "\n[Network]\n"
            else:
                content = interface_network_content(name, mode, address, mtu, state=update.state)
            path = interface_network_path(name, stage_dir)

        write_staged_file(path, content)
        return {"name": name, "staged": True, "message": "Interface change staged; press Apply to activate it"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/api/interfaces")
async def create_interface(create: InterfaceCreate):
    validate_ifname(create.name)
    kind = "dummy" if create.kind in {"dummy", "dummy6"} else create.kind
    if kind != "dummy":
        raise HTTPException(400, "Supported interface type: dummy")
    if create.mtu is not None and not 576 <= create.mtu <= 65535:
        raise HTTPException(400, "MTU must be between 576 and 65535")
    stage_dir = prepare_staging()
    write_staged_file(stage_dir / f"{NETWORKD_PREFIX}{create.name}.netdev", f"[NetDev]\nName={create.name}\nKind={kind}\n")
    if create.mtu is not None:
        write_staged_file(stage_dir / f"{NETWORKD_PREFIX}interface-{create.name}.network", f"[Match]\nName={create.name}\n\n[Link]\nMTUBytes={create.mtu}\n")
    return {"name": create.name, "staged": True, "message": "Interface creation staged; press Apply to activate it"}


@app.delete("/api/interfaces/{name}")
async def delete_interface(name: str):
    if name in {"lo", "lan0", "wan0"}:
        raise HTTPException(400, "Protected interface")
    stage_dir = prepare_staging()
    paths = [
        stage_dir / f"{NETWORKD_PREFIX}{name}.netdev",
        stage_dir / f"{NETWORKD_PREFIX}{name}.network",
        stage_dir / f"{NETWORKD_PREFIX}interface-{name}.network",
    ]
    # Also remove bridge-member definitions owned by the manager.
    paths.extend(stage_dir.glob(f"{NETWORKD_PREFIX}*-member-{name}.network"))
    removed = False
    for path in paths:
        if path.exists():
            path.unlink()
            removed = True
    if not removed:
        raise HTTPException(409, "Interface is not managed by this application")
    return {"name": name, "staged": True, "message": "Interface deletion staged; press Apply to activate it"}


async def get_interface_stats(name: str) -> dict[str, int]:
    base = Path("/sys/class/net") / name / "statistics"
    result: dict[str, int] = {}
    for key, filename in (("rx_bytes", "rx_bytes"), ("tx_bytes", "tx_bytes")):
        try:
            result[key] = int((base / filename).read_text().strip())
        except (FileNotFoundError, ValueError):
            result[key] = 0
    return result


def format_rate(bits_per_second: float) -> str:
    units = ("bps", "Kbps", "Mbps", "Gbps")
    value = max(0.0, bits_per_second)
    unit = 0
    while value >= 1000 and unit < len(units) - 1:
        value /= 1000
        unit += 1
    return f"{value:.1f} {units[unit]}"


async def get_neighbor_count(interface: str | None = None) -> int:
    args = ["ip", "-j", "neigh", "show"]
    if interface:
        args += ["dev", interface]
    try:
        raw = await run_command(*args)
        neighbors = json.loads(raw)
        return sum(1 for n in neighbors if n.get("lladdr") and n.get("nud") not in ("FAILED", "INCOMPLETE"))
    except Exception:
        return 0


async def get_log_lines(lines: int = 50) -> list[str]:
    lines = max(1, min(lines, 500))
    if not shutil.which("journalctl"):
        raise RuntimeError("journalctl is not installed")
    raw = await run_command("journalctl", "--no-pager", "-n", str(lines), "-o", "short-iso")
    return [line for line in raw.splitlines() if line.strip()]


@app.get("/api/bridges")
async def bridges():
    try:
        return await get_bridges()
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/api/vlans")
async def vlans():
    try:
        return await get_vlans()
    except Exception as exc:
        raise HTTPException(500, str(exc))




@app.post("/api/bridges")
async def create_bridge(create: BridgeCreate):
    try:
        validate_ifname(create.name)
        if create.name in {"lo"}:
            raise HTTPException(400, "Protected interface name")
        mode, addr = validate_ipv4_config(create.address_mode, create.address)
        if any(m == create.name for m in create.members):
            raise HTTPException(400, "A bridge cannot contain itself")
        await write_bridge_networkd(create.name, create.stp, create.members, mode, addr, prepare_staging())
        return {"name": create.name, "staged": True, "message": "Bridge change staged; press Apply to activate it"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.delete("/api/bridges/{name}")
async def delete_bridge(name: str):
    if name in {"lo", "lan0", "wan0"}:
        raise HTTPException(400, "Protected bridge")
    bridges_now = await get_bridges()
    current = next((b for b in bridges_now if b["name"] == name), None)
    if current is None:
        raise HTTPException(404, "Bridge not found")

    stage_dir = prepare_staging()
    paths = [
        bridge_netdev_path(name, stage_dir),
        bridge_network_path(name, stage_dir),
    ]
    paths.extend(stage_dir.glob(f"{NETWORKD_PREFIX}{name}-member-*.network"))
    removed = False
    for path in paths:
        if path.exists():
            path.unlink()
            removed = True

    if not removed:
        raise HTTPException(409, "Bridge is externally provisioned; it cannot be deleted by Router Manager")
    return {"name": name, "staged": True, "message": "Router Manager bridge settings removed; externally provisioned device remains"}


@app.put("/api/bridges/{name}")
async def update_bridge(name: str, update: BridgeUpdate):
    bridges_now = await get_bridges()
    current = next((b for b in bridges_now if b["name"] == name), None)
    if current is None:
        raise HTTPException(404, "Bridge not found")
    try:
        stp = current.get("stp_enabled") if update.stp is None else update.stp
        members = current.get("members", []) if update.members is None else update.members
        stage_dir = prepare_staging()
        managed_network = bridge_network_path(name, stage_dir)
        live_managed_network = bridge_network_path(name)
        if update.address_mode is None and managed_network.exists():
            persisted = managed_network.read_text()
            address_mode = "dhcp" if "DHCP=ipv4" in persisted else "static"
            address = next((line.split("=", 1)[1].strip() for line in persisted.splitlines() if line.startswith("Address=")), None)
        else:
            address_mode = update.address_mode or ("static" if any("." in a and ":" not in a for a in current.get("addresses", [])) else "dhcp")
            address = update.address if update.address_mode else next((a for a in current.get("addresses", []) if ":" not in a), None)
        mode, addr = validate_ipv4_config(address_mode, address)
        managed_bridge = bridge_netdev_path(name, stage_dir).exists()
        if managed_bridge:
            await write_bridge_networkd(name, bool(stp), members, mode, addr, stage_dir)
        else:
            # Do not recreate or take ownership of a bridge provisioned elsewhere.
            # Networkd can configure addresses and membership on an existing bridge.
            if update.stp is not None and update.stp != current.get("stp_enabled"):
                raise HTTPException(409, "STP on an externally provisioned bridge must be changed by its owner")
            write_staged_file(bridge_network_path(name, stage_dir), bridge_network_content(name, mode, addr))
            for member in members:
                validate_ifname(member)
                write_staged_file(bridge_member_network_path(name, member, stage_dir),
                                  bridge_member_network_content(member, name))
            # Remove stale manager-owned member assignments for this bridge.
            for old_member in stage_dir.glob(f"{NETWORKD_PREFIX}{name}-member-*.network"):
                member_name = old_member.name[len(f"{NETWORKD_PREFIX}{name}-member-"):-len(".network")]
                if member_name not in members:
                    old_member.unlink()
        return {"name": name, "staged": True, "message": "Bridge change staged; press Apply to activate it"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/api/vlans")
async def create_vlan(create: VlanCreate):
    try:
        validate_ifname(create.name)
        validate_ifname(create.parent)
        if not 1 <= create.vlan_id <= 4094:
            raise HTTPException(400, "VLAN ID must be 1-4094")
        await write_vlan_networkd(create.name, create.parent, create.vlan_id, create.mtu, create.address_mode, create.address, prepare_staging())
        return {"name": create.name, "staged": True, "message": "VLAN change staged; press Apply to activate it"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.delete("/api/vlans/{name}")
async def delete_vlan(name: str):
    vlan = next((v for v in await get_vlans() if v["name"] == name), None)
    if vlan is None:
        raise HTTPException(404, "VLAN not found")

    stage_dir = prepare_staging()
    netdev = vlan_netdev_path(name, stage_dir)
    network = vlan_network_path(name, stage_dir)
    parent = vlan.get("parent")
    removed = False

    for path in (netdev, network):
        if path.exists():
            path.unlink()
            removed = True

    # Remove the VLAN attachment from the staged parent networkd file.
    # This prevents networkd from recreating the VLAN relationship after the
    # VLAN netdev itself has been removed.
    if parent:
        for path in stage_dir.glob(f"{NETWORKD_PREFIX}*.network"):
            if not path.is_file():
                continue
            lines = path.read_text().splitlines()
            new_lines = []
            changed = False
            for line in lines:
                if line.strip().lower() == f"vlan={name}".lower():
                    changed = True
                    continue
                new_lines.append(line)
            if changed:
                while new_lines and not new_lines[-1].strip():
                    new_lines.pop()
                write_staged_file(path, "\n".join(new_lines) + "\n")
                removed = True

    if not removed:
        raise HTTPException(409, "VLAN is externally provisioned; it cannot be deleted by Router Manager")
    return {"name": name, "staged": True, "message": "Router Manager VLAN settings removed; externally provisioned device remains"}


@app.put("/api/vlans/{name}")
async def update_vlan(name: str, update: VlanUpdate):
    vlan = next((v for v in await get_vlans() if v["name"] == name), None)
    if vlan is None:
        raise HTTPException(404, "VLAN not found")
    try:
        # Read the persisted manager file to retain parent and VLAN ID on an edit.
        stage_dir = prepare_staging()
        netdev = vlan_netdev_path(name, stage_dir)
        if not netdev.exists():
            netdev = vlan_netdev_path(name)
        parent = vlan.get("parent")
        vlan_id = vlan.get("vlan_id")
        if not parent or not vlan_id:
            raise HTTPException(409, "Cannot determine VLAN parent or VLAN ID")
        # Existing externally provisioned VLANs do not need a new .netdev:
        # configure their networkd settings without claiming their creation.
        externally_provisioned = not netdev.exists()
        current_addr = next((a for a in vlan.get("addresses", []) if ":" not in a), None)
        mode = update.address_mode or ("static" if current_addr else "dhcp")
        address = update.address if update.address_mode else current_addr
        if externally_provisioned:
            path = vlan_network_path(name, stage_dir)
            content = vlan_network_content(name, mode, address)
            links = []
            if update.mtu is not None:
                if not 576 <= update.mtu <= 65535:
                    raise HTTPException(400, "MTU must be between 576 and 65535")
                links.append(f"MTUBytes={update.mtu}")
            if update.state is not None:
                if update.state not in ("up", "down"):
                    raise HTTPException(400, "State must be up or down")
                links.append(f"ActivationPolicy={update.state}")
            if links:
                content = content.replace("[Network]\\n", "[Link]\\n" + "\\n".join(links) + "\\n\\n[Network]\\n", 1)
            write_staged_file(path, content)
        else:
            await write_vlan_networkd(name, parent, int(vlan_id), update.mtu or vlan.get("mtu"), mode, address, stage_dir, update.state)
        return {"name": name, "staged": True, "message": "VLAN change staged; press Apply to activate it"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/api/dashboard")
async def dashboard():
    items = await get_interfaces()
    wan = next((x for x in items if x["name"] == "wan0"), None)
    wan_name = wan["name"] if wan else None
    stats = await get_interface_stats(wan_name) if wan_name else {"rx_bytes": 0, "tx_bytes": 0}

    # These values are intentionally live-only. If the router does not expose a
    # value, return null rather than inventing a value for the dashboard.
    clients = await get_neighbor_count("lan0") if any(x["name"] == "lan0" for x in items) else 0
    logs = await get_log_lines(4)

    return {
        "internet": {
            "connected": bool(wan and wan["operstate"] == "up"),
            "address": next((x for x in (wan or {}).get("addresses", []) if ":" not in x), None),
        },
        "clients": clients,
        "traffic": {
            "rx_bytes": stats["rx_bytes"],
            "tx_bytes": stats["tx_bytes"],
            "download": "—",
            "upload": "—",
        },
        "system": {
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "kernel": platform.release(),
            "cpu_percent": read_cpu_percent(),
        },
        "interfaces": items,
        "recent_events": logs,
    }


@app.get("/api/logs")
async def logs(lines: int = 100):
    try:
        return await get_log_lines(lines)
    except Exception as exc:
        raise HTTPException(503, str(exc))


@app.get("/api/config/download")
async def download_applied_config():
    """Download only committed settings; never export an unapplied draft."""
    applied = _read_applied_config_json()
    if applied is None:
        applied = _bootstrap_applied_config_json()
    return FileResponse(
        APPLIED_CONFIG_JSON,
        media_type="application/json",
        filename="config.json",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/system/{action}")
async def system_power_action(action: str):
    """Queue a real systemd power action after the HTTP response is delivered."""
    if action not in ("reboot", "shutdown"):
        raise HTTPException(status_code=404, detail="Unknown system action")
    if not Path("/run/systemd/system").exists():
        raise HTTPException(status_code=503, detail="systemd is not running")
    if os.geteuid() != 0:
        raise HTTPException(status_code=403, detail="Router Manager must run as root to reboot or shut down the router")
    executable = shutil.which("systemctl")
    if not executable:
        raise HTTPException(status_code=503, detail="systemctl not found")
    verb = "reboot" if action == "reboot" else "poweroff"
    # --no-block asks systemd to queue the operation without waiting for completion.
    # Delay briefly so the HTTP response can reach the browser before networking stops.
    async def launch():
        await asyncio.sleep(1.5)
        try:
            subprocess.Popen(
                [executable, "--no-block", verb],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
            )
        except OSError:
            pass
    asyncio.create_task(launch())
    return {"status": "scheduled", "action": action}


@app.post("/api/config/restore")
async def stage_restored_config(payload: dict = Body(...)):
    """Import a backup as a draft. Never touch running services here."""
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise HTTPException(400, "Expected Router Manager config.json version 1")
    if "pending" in payload:
        raise HTTPException(400, "Backups must contain applied configuration only (no pending section)")
    if not isinstance(payload.get("files"), dict) or not isinstance(payload.get("routes"), list):
        raise HTTPException(400, "Backup must contain files and routes")
    if len(json.dumps(payload)) > 2_000_000:
        raise HTTPException(413, "Configuration backup is too large")
    files = {}
    for name, content in payload["files"].items():
        if (not isinstance(name, str) or not name.startswith(NETWORKD_PREFIX)
                or Path(name).name != name or not name.endswith((".network", ".netdev"))
                or not isinstance(content, str)):
            raise HTTPException(400, f"Invalid managed networkd file: {name!r}")
        files[name] = content
    try:
        routes = [_validate_static_route(StaticRoute(
            destination=r.get("dst", "default"), gateway=r.get("gateway"),
            dev=r.get("dev"), metric=int(r.get("metric", 0))
        )) for r in payload["routes"]]
        kea = _normalize_kea_dhcp_config(payload["kea_dhcp"]) if "kea_dhcp" in payload else None
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise HTTPException(400, f"Invalid backup configuration: {exc}") from exc

    firewall_restore = _normalize_firewall(payload["firewall"]) if "firewall" in payload else None
    # A restore replaces any earlier draft, but does not install files or restart services.
    applied = _read_applied_config_json()
    if applied is None:
        applied = _bootstrap_applied_config_json()
    if kea is None and applied.get("kea_dhcp") is not None:
        raise HTTPException(400, "Backup has no kea_dhcp section; restoring would leave existing Kea DHCP unchanged")
    discard_staging()
    NETWORKD_STAGING_DIR.mkdir(parents=True, exist_ok=True)
    for old in NETWORKD_STAGING_DIR.glob(f"{NETWORKD_PREFIX}*"):
        if old.is_file():
            old.unlink()
    for name, content in files.items():
        (NETWORKD_STAGING_DIR / name).write_text(content)
    NETWORKD_STAGING_MARKER.write_text("pending\n")
    route_cfg = {"original": applied.get("routes", []), "desired": routes}
    _write_pending_config_json(files, route_config=route_cfg, kea_dhcp=kea)
    if firewall_restore is not None:
        root = json.loads(APPLIED_CONFIG_JSON.read_text())
        root["pending"]["firewall"] = firewall_restore
        APPLIED_CONFIG_JSON.write_text(json.dumps(root, indent=2) + "\n")
    changes = _staged_config_changes()
    return {"message": "Backup staged; press Apply Changes to activate it",
            "pending": bool(changes), "count": len(changes)}


@app.get("/api/config/status")
async def config_status():
    changes = _staged_config_changes()
    return {
        "pending": bool(changes),
        "count": len(changes),
        "changes": changes,
        "storage_file": str(APPLIED_CONFIG_JSON),
        "pending_section": "pending",
        "applied_storage_file": str(APPLIED_CONFIG_JSON),
    }


async def apply_staged_networkd() -> list[str]:
    if not has_pending_config():
        return []
    ensure_networkd_dir()
    names: set[str] = set()
    pending_payload = _pending_json_payload()
    applied_payload = _read_applied_config_json() or {"version": 1, "files": {}, "routes": []}
    kea_dhcp = pending_payload.get("kea_dhcp", applied_payload.get("kea_dhcp"))
    if kea_dhcp is not None:
        kea_dhcp = _normalize_kea_dhcp_config(kea_dhcp)
        await _validate_kea_dhcp_install(kea_dhcp)

    # Install staged network-manager files only after the user presses Apply.
    if NETWORKD_STAGING_MARKER.exists():
        NETWORKD_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        staged_names = {p.name for p in NETWORKD_STAGING_DIR.glob(f"{NETWORKD_PREFIX}*") if p.is_file()}
        active_paths = [p for p in NETWORKD_DIR.glob(f"{NETWORKD_PREFIX}*") if p.is_file()]
        for path in active_paths:
            backup = NETWORKD_BACKUP_DIR / path.name
            if not backup.exists():
                backup.write_bytes(path.read_bytes())
            if path.name not in staged_names:
                names.update(_networkd_names_from_content(path.read_text()))
                names.update(_networkd_names_from_netdev(path.read_text()))
                path.unlink()

        for staged in NETWORKD_STAGING_DIR.glob(f"{NETWORKD_PREFIX}*"):
            if not staged.is_file():
                continue
            target = NETWORKD_DIR / staged.name
            staged_content = staged.read_text()
            if not target.exists() or target.read_text() != staged_content:
                _backup_networkd_file(target)
                _write_networkd_atomic(target, staged_content)
                names.update(_networkd_names_from_content(staged_content))
                names.update(_networkd_names_from_netdev(staged_content))

    # Keep prior applied routes when this Apply contains no route edits.
    if "route_config" in pending_payload:
        route_cfg = pending_payload.get("route_config") or {}
        routes = route_cfg.get("desired", [])
        for route in route_cfg.get("original", []) + routes:
            if route.get("dev"):
                names.add(route["dev"])
    else:
        routes = applied_payload.get("routes", [])
        for route in routes:
            if route.get("dev"):
                names.add(route["dev"])

    names.update(_apply_static_routes_to_networkd(routes))
    await _remove_legacy_route_service()

    if names:
        await networkd_reload(*sorted(names))
    if kea_dhcp is not None:
        await _apply_kea_dhcp_config(kea_dhcp)
    firewall_cfg = pending_payload.get("firewall")
    if firewall_cfg is not None:
        await _apply_firewall(_normalize_firewall(firewall_cfg))

    # Commit applied state only after the requested services accepted the config.
    _write_applied_config_json(routes, kea_dhcp)
    if firewall_cfg is not None:
        root = json.loads(APPLIED_CONFIG_JSON.read_text())
        root["firewall"] = _normalize_firewall(firewall_cfg)
        APPLIED_CONFIG_JSON.write_text(json.dumps(root, indent=2) + "\n")
    discard_staging()
    return sorted(names)


@app.post("/api/config/discard")
async def discard_config():
    try:
        changes = _staged_config_changes()
        if not changes:
            discard_staging()
            return {"message": "No unapplied network configuration changes", "discarded": 0}
        count = len(changes)
        discard_staging()
        return {"message": "Unapplied network configuration changes discarded", "discarded": count}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/api/config/apply")
async def apply_config():
    try:
        had_pending = has_pending_config()
        names = await apply_staged_networkd()
        if not had_pending:
            return {"message": "No pending network configuration changes"}
        return {"message": "Pending configuration applied", "interfaces": names}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/api/dhcp")
async def get_dhcp_config():
    pending = _pending_json_payload()
    applied = _read_applied_config_json() or {"version": 1, "files": {}, "routes": []}
    config = pending.get("kea_dhcp", applied.get("kea_dhcp"))
    interfaces = await get_interfaces()
    if config is None:
        config = _default_kea_dhcp_config(interfaces)
    service, active, enabled = await _kea_service_state()
    leases = _read_kea_leases(config)
    return {
        "config": config,
        "service": service,
        "active": active,
        "service_enabled": enabled,
        "installed": bool(shutil.which("kea-dhcp4")) and service is not None,
        "config_path": str(KEA_DHCP4_CONFIG),
        "leases": leases,
        "interfaces": [
            {"name": item["name"], "type": item.get("type"), "addresses": item.get("addresses", [])}
            for item in interfaces if item["name"] != "lo"
        ],
        "pending": "kea_dhcp" in pending and config != applied.get("kea_dhcp"),
    }


@app.post("/api/dhcp")
async def stage_dhcp_config(config: KeaDhcpConfig):
    normalized = _normalize_kea_dhcp_config(config.model_dump())
    interfaces = await get_interfaces()
    selected_interface = next((item for item in interfaces if item["name"] == normalized["interface"]), None)
    if selected_interface is None:
        raise HTTPException(400, f"Interface {normalized['interface']} does not exist")
    if normalized["enabled"] and normalized["router"]:
        configured_ipv4 = set()
        for address in selected_interface.get("addresses", []):
            try:
                ipif = ipaddress.ip_interface(address)
                if ipif.version == 4:
                    configured_ipv4.add(str(ipif.ip))
            except ValueError:
                continue
        if configured_ipv4 and normalized["router"] not in configured_ipv4:
            raise HTTPException(400, "The DHCP router address must match an IPv4 address currently assigned to the selected interface")
    prepare_staging()
    payload = _pending_json_payload()
    files = payload.get("files", {})
    _write_pending_config_json(files, kea_dhcp=normalized)
    return {
        "message": "Kea DHCP configuration staged; the live DHCP server is unchanged",
        "config": normalized,
    }


@app.get("/api/routes")
async def routes():
    return json.loads(await run_command("ip", "-j", "route", "show"))


@app.get("/api/routes/pending")
async def pending_routes():
    payload = _pending_json_payload()
    cfg = payload.get("route_config")
    return {"desired": (cfg or {}).get("desired", []), "original": (cfg or {}).get("original", [])}


@app.post("/api/routes")
async def stage_static_route(route: StaticRoute):
    item = _validate_static_route(route)
    prepare_staging()
    payload = _pending_json_payload()
    cfg = payload.get("route_config")
    if cfg is None:
        live = await _live_static_routes()
        cfg = {"original": live, "desired": list(live)}
    desired = {_route_key(r): r for r in cfg.get("desired", [])}
    desired[_route_key(item)] = item
    cfg["desired"] = list(desired.values())
    files = payload.get("files", {})
    _write_pending_config_json(files, cfg)
    return {"message": "Static route staged; live routing table is unchanged", "route": item}


@app.delete("/api/routes")
async def unstage_static_route(route: RouteDelete):
    item = _validate_static_route(StaticRoute(**route.model_dump()))
    prepare_staging()
    payload = _pending_json_payload()
    cfg = payload.get("route_config")
    if cfg is None:
        live = await _live_static_routes()
        cfg = {"original": live, "desired": list(live)}
    key = _route_key(item)
    cfg["desired"] = [r for r in cfg.get("desired", []) if _route_key(r) != key]
    _write_pending_config_json(payload.get("files", {}), cfg)
    return {"message": "Route removal staged; live routing table is unchanged"}


@app.get("/api/firewall/config")
async def get_firewall_config():
    applied = _read_applied_config_json() or {}
    pending = _pending_json_payload()
    return {"config": pending.get("firewall", applied.get("firewall", {"interfaces": [], "nat": [], "pat": []})),
            "pending": "firewall" in pending}


@app.post("/api/firewall/config")
async def stage_firewall_config(config: FirewallConfig):
    normalized = _normalize_firewall(config.model_dump())
    applied = _read_applied_config_json() or _bootstrap_applied_config_json()
    root = json.loads(APPLIED_CONFIG_JSON.read_text())
    pending = root.get("pending") or {"version": 1, "files": applied.get("files", {})}
    pending["firewall"] = normalized
    root["pending"] = pending
    tmp = APPLIED_CONFIG_JSON.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(root, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(APPLIED_CONFIG_JSON)
    return {"message": "Firewall changes staged; press Apply Changes"}


@app.get("/api/firewall")
async def firewall():
    if not shutil.which("nft"):
        raise HTTPException(503, "nft command is not installed")
    try:
        raw = await run_command("nft", "-j", "-a", "list", "ruleset")
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(500, "nft returned invalid JSON") from exc
    except Exception as exc:
        raise HTTPException(503, str(exc))


@app.on_event("startup")
async def startup_sync_systemd_networkd_from_json():
    """Import installed networkd files into config.json; never apply pending edits."""
    try:
        applied = refresh_config_json_from_networkd()
        if "kea_dhcp" in applied:
            await _sync_kea_dhcp_from_applied_json(applied["kea_dhcp"])
        if "firewall" in applied:
            try:
                await _apply_firewall(_normalize_firewall(applied["firewall"]))
            except Exception as exc:
                print(f"WARNING: Could not restore firewall at startup: {exc}", flush=True)
    except Exception as exc:
        raise RuntimeError(f"Router Manager startup configuration import failed: {exc}") from exc


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=80, reload=False)

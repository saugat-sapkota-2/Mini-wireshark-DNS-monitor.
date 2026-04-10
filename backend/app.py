from collections import Counter, deque
from datetime import datetime
from pathlib import Path
import re
import socket
import subprocess
import time
from typing import Any, Dict

from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

from sniffer import PacketSniffer

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
app.config["SECRET_KEY"] = "mini-wireshark-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

MAX_REQUEST_ROWS = 200
request_history = deque(maxlen=MAX_REQUEST_ROWS)
domain_counter: Counter[str] = Counter()
devices: Dict[str, Dict[str, Any]] = {}
arp_cache: Dict[str, str] = {}
arp_cache_updated_at = 0.0


def refresh_arp_cache(force: bool = False) -> None:
    """Refresh ARP cache so MAC fallback works when packet lacks Ethernet layer."""
    global arp_cache_updated_at, arp_cache

    now = time.time()
    if not force and now - arp_cache_updated_at < 15:
        return

    try:
        output = subprocess.check_output(["arp", "-a"], text=True, encoding="utf-8", errors="ignore")
    except Exception:
        return

    mac_entries: Dict[str, str] = {}
    for line in output.splitlines():
        # Works for common Windows and Unix-like arp output variants.
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{14,17})", line)
        if not match:
            continue
        ip_addr, mac_addr = match.groups()
        mac_entries[ip_addr] = mac_addr.replace("-", ":").lower()

    if mac_entries:
        arp_cache = mac_entries
        arp_cache_updated_at = now


def resolve_device_name(ip_addr: str) -> str:
    try:
        hostname = socket.gethostbyaddr(ip_addr)[0]
        if hostname and hostname != ip_addr:
            return hostname
    except Exception:
        pass

    refresh_arp_cache()
    mac_addr = arp_cache.get(ip_addr, "")
    if mac_addr:
        return f"Device-{mac_addr[-5:].replace(':', '').upper()}"

    return "Unknown Device"


def get_device_mac(ip_addr: str, packet_mac: str) -> str:
    if packet_mac and packet_mac != "Unknown":
        return packet_mac

    refresh_arp_cache()
    return arp_cache.get(ip_addr, "Unknown")


def upsert_device(ip_addr: str, mac_addr: str, device_name: str, request: Dict[str, Any] | None = None) -> None:
    if ip_addr not in devices:
        devices[ip_addr] = {
            "name": device_name,
            "mac": mac_addr,
            "requests": deque(maxlen=MAX_REQUEST_ROWS),
            "last_seen": "-",
        }

    entry = devices[ip_addr]
    if device_name and device_name != "Unknown Device":
        entry["name"] = device_name
    if mac_addr and mac_addr != "Unknown":
        entry["mac"] = mac_addr

    if request is not None:
        entry["requests"].appendleft(request)
        entry["last_seen"] = request.get("timestamp", "-")


def get_device_snapshot() -> list[Dict[str, Any]]:
    entries = []
    for ip, data in devices.items():
        requests = list(data.get("requests", []))
        unique_domains = len({item.get("domain", "") for item in requests if item.get("domain")})
        last_domain = requests[0].get("domain", "-") if requests else "-"
        entries.append(
            {
                "ip": ip,
                "name": data.get("name", "Unknown Device"),
                "mac": data.get("mac", "Unknown"),
                "total_requests": len(requests),
                "unique_domains": unique_domains,
                "last_domain": last_domain,
                "last_seen": data.get("last_seen", "-"),
            }
        )

    entries.sort(key=lambda row: row["total_requests"], reverse=True)
    return entries


def get_top_active_devices(limit: int = 5) -> list[Dict[str, Any]]:
    snapshot = get_device_snapshot()
    return snapshot[:limit]


def get_popular_domains(limit: int = 8) -> list[Dict[str, Any]]:
    return [{"domain": domain, "count": count} for domain, count in domain_counter.most_common(limit)]


def broadcast_dns_event(event: Dict[str, Any]) -> None:
    event["timestamp"] = datetime.now().strftime("%H:%M:%S")

    domain = str(event.get("domain", "")).lower().strip()
    device_ip = str(event.get("device_ip", ""))
    packet_mac = str(event.get("device_mac", "Unknown"))

    if not domain or not device_ip:
        return

    device_mac = get_device_mac(device_ip, packet_mac)
    device_name = resolve_device_name(device_ip)

    event["device_mac"] = device_mac
    event["device_name"] = device_name

    domain_counter[domain] += 1
    event["popular"] = domain_counter[domain] >= 4
    request_history.appendleft(event)

    upsert_device(device_ip, device_mac, device_name, request=event)

    socketio.emit("dns_request", event)
    socketio.emit("device_snapshot", get_device_snapshot())
    socketio.emit("top_devices", get_top_active_devices())
    socketio.emit("popular_domains", get_popular_domains())


sniffer = PacketSniffer(on_dns_event=broadcast_dns_event)


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def static_proxy(path: str):
    return send_from_directory(FRONTEND_DIR, path)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@socketio.on("connect")
def handle_connect():
    interfaces = sniffer.list_interfaces()
    emit("interfaces", interfaces)
    emit("default_interface", {"interface": sniffer.get_default_interface()})
    emit(
        "permissions",
        {
            "allowed": sniffer.has_capture_permissions(),
            "message": "Run terminal as Administrator/root if capture fails.",
        },
    )
    emit("history", list(request_history))
    emit("device_snapshot", get_device_snapshot())
    emit("top_devices", get_top_active_devices())
    emit("popular_domains", get_popular_domains())
    emit(
        "limitation_note",
        {
            "text": "HTTPS traffic is encrypted. Only DNS/domain-level visibility is available.",
        },
    )


@socketio.on("refresh_interfaces")
def handle_refresh_interfaces():
    emit("interfaces", sniffer.list_interfaces())
    emit("default_interface", {"interface": sniffer.get_default_interface()})


@socketio.on("start_capture")
def handle_start_capture(data):
    interface = data.get("interface", "") or sniffer.get_default_interface()
    domain_filter = data.get("domainFilter", "")

    result = sniffer.start(interface=interface, domain_filter=domain_filter)
    emit("capture_status", result)


@socketio.on("stop_capture")
def handle_stop_capture():
    result = sniffer.stop()
    emit("capture_status", result)


@socketio.on("scan_devices")
def handle_scan_devices(data):
    interface = data.get("interface", "")
    if not interface:
        emit("scan_status", {"status": "error", "message": "Select an interface first."})
        return

    try:
        refresh_arp_cache(force=True)
        devices = sniffer.arp_scan(interface)
    except Exception as exc:
        emit("scan_status", {"status": "error", "message": f"ARP scan failed: {exc}"})
        return

    for device in devices:
        ip = device.get("ip", "")
        mac = device.get("mac", "Unknown")
        if not ip:
            continue

        device_name = resolve_device_name(ip)
        upsert_device(ip, mac, device_name)

    emit("scan_status", {"status": "ok", "message": f"Discovered {len(devices)} device(s)."})
    socketio.emit("device_snapshot", get_device_snapshot())


if __name__ == "__main__":
    # Threading mode keeps compatibility with newer Python versions.
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

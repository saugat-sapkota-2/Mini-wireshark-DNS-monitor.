import ctypes
import ipaddress
import os
import re
import socket
from typing import Any, Callable, Dict, List, Optional

from scapy.all import ARP, AsyncSniffer, DNS, DNSQR, Ether, IP, conf, get_if_addr, get_if_list, srp


class PacketSniffer:
    """Capture DNS activity and provide interface helpers."""

    known_domains = {
        "googleapis.com": "Google Service",
        "facebook.com": "Facebook",
        "youtube.com": "YouTube",
        "microsoft.com": "Microsoft",
    }

    exact_domain_labels = {
        "optimizationguide-pa.googleapis.com": "Google Optimization Service",
        "mobile.events.data.microsoft.com": "Microsoft Telemetry",
        "firestore.googleapis.com": "Google Firebase",
    }

    wifi_keywords = ("wi-fi", "wifi", "wireless", "wlan")

    def __init__(self, on_dns_event: Callable[[Dict[str, Any]], None]) -> None:
        self.on_dns_event = on_dns_event
        self.sniffer: Optional[AsyncSniffer] = None
        self.running = False
        self.selected_interface: Optional[str] = None
        self.domain_filter: str = ""

    @staticmethod
    def _is_guid_like(value: str) -> bool:
        return value.startswith("{") and value.endswith("}")

    @staticmethod
    def _interface_display_name(iface: str) -> str:
        """Return friendly adapter label when available (especially on Windows)."""
        try:
            iface_obj = conf.ifaces[iface]
        except Exception:
            return iface

        candidates = [
            str(getattr(iface_obj, "description", "")).strip(),
            str(getattr(iface_obj, "name", "")).strip(),
            str(getattr(iface_obj, "network_name", "")).strip(),
        ]

        for candidate in candidates:
            if not candidate:
                continue
            if candidate == iface:
                continue
            if PacketSniffer._is_guid_like(candidate):
                continue
            return candidate

        return iface

    @staticmethod
    def _interface_capture_name(iface: str) -> str:
        """Return interface value suitable for Scapy capture calls."""
        try:
            iface_obj = conf.ifaces[iface]
        except Exception:
            return iface

        network_name = str(getattr(iface_obj, "network_name", "")).strip()
        if network_name:
            return network_name

        return iface

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        return domain.strip().rstrip(".").lower()

    @staticmethod
    def _is_active_interface(ip_addr: str) -> bool:
        if not ip_addr or ip_addr in {"N/A", "0.0.0.0", "127.0.0.1"}:
            return False
        return True

    @staticmethod
    def _looks_like_hash_label(label: str) -> bool:
        if len(label) < 14:
            return False

        if re.fullmatch(r"[a-f0-9]{14,}", label):
            return True

        # Label with lots of digits and mixed symbols is usually a device/session ID.
        digit_count = sum(ch.isdigit() for ch in label)
        if len(label) > 16 and digit_count >= 6 and re.fullmatch(r"[a-z0-9-]+", label):
            return True

        return False

    def _clean_domain(self, raw_domain: str) -> str:
        normalized = self._normalize_domain(raw_domain)
        if not normalized:
            return normalized

        labels = normalized.split(".")
        filtered = [label for label in labels if not self._looks_like_hash_label(label)]
        if len(filtered) < 2:
            return normalized

        return ".".join(filtered)

    def _friendly_domain_name(self, clean_domain: str) -> str:
        if clean_domain in self.exact_domain_labels:
            return self.exact_domain_labels[clean_domain]

        for suffix, label in self.known_domains.items():
            if clean_domain.endswith(suffix):
                return label

        return clean_domain

    def _choose_default_interface(self, interfaces: List[Dict[str, str]]) -> str:
        if not interfaces:
            return ""

        active = [item for item in interfaces if self._is_active_interface(item.get("ip", ""))]

        def preferred(items: List[Dict[str, str]]) -> Optional[str]:
            for item in items:
                haystack = (
                    f"{item.get('display', '')} {item.get('name', '')} {item.get('capture', '')}"
                ).lower()
                if any(keyword in haystack for keyword in self.wifi_keywords):
                    return item.get("capture") or item.get("name") or ""
            return None

        wifi_active = preferred(active)
        if wifi_active:
            return wifi_active

        wifi_any = preferred(interfaces)
        if wifi_any:
            return wifi_any

        if active:
            return active[0].get("capture") or active[0].get("name") or ""

        return interfaces[0].get("capture") or interfaces[0].get("name") or ""

    @staticmethod
    def has_capture_permissions() -> bool:
        """Return True when the process likely has packet capture permissions."""
        if os.name == "nt":
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False

        if hasattr(os, "geteuid"):
            return os.geteuid() == 0

        return False

    @staticmethod
    def list_interfaces() -> List[Dict[str, str]]:
        """Get available network interfaces from Scapy."""
        interfaces: List[Dict[str, str]] = []
        for iface in get_if_list():
            ip_addr = "N/A"
            try:
                candidate = get_if_addr(iface)
                if candidate:
                    ip_addr = candidate
            except Exception:
                ip_addr = "N/A"

            interfaces.append(
                {
                    "name": iface,
                    "display": PacketSniffer._interface_display_name(iface),
                    "capture": PacketSniffer._interface_capture_name(iface),
                    "ip": ip_addr,
                }
            )

        # Remove duplicates while preserving order.
        seen = set()
        unique_interfaces = []
        for item in interfaces:
            key = item["name"]
            if key not in seen:
                seen.add(key)
                unique_interfaces.append(item)

        return unique_interfaces

    def _resolve_selected_interface(self, interface: str) -> Optional[Dict[str, str]]:
        available = self.list_interfaces()
        for item in available:
            if interface in {item.get("name", ""), item.get("capture", "")}:  # pragma: no branch
                return item
        return None

    def get_default_interface(self) -> str:
        interfaces = self.list_interfaces()
        return self._choose_default_interface(interfaces)

    def _extract_dns_event(self, packet: Any) -> Optional[Dict[str, Any]]:
        if not packet.haslayer(IP):
            return None

        if not packet.haslayer(DNS):
            return None

        dns_layer = packet[DNS]
        if int(getattr(dns_layer, "qr", 1)) != 0:
            return None

        if not packet.haslayer(DNSQR):
            return None

        query_raw = packet[DNSQR].qname
        if isinstance(query_raw, bytes):
            raw_domain = query_raw.decode("utf-8", errors="ignore")
        else:
            raw_domain = str(query_raw)

        raw_domain = self._normalize_domain(raw_domain)
        clean_domain = self._clean_domain(raw_domain)
        if not clean_domain:
            return None

        if self.domain_filter and self.domain_filter not in clean_domain:
            return None

        readable_domain = self._friendly_domain_name(clean_domain)

        src_mac = "Unknown"
        if packet.haslayer(Ether):
            src_mac = str(packet[Ether].src)

        return {
            "device_ip": str(packet[IP].src),
            "dst_ip": str(packet[IP].dst),
            "device_mac": src_mac,
            "raw_domain": raw_domain,
            "domain": clean_domain,
            "readable_domain": readable_domain,
            "protocol": "DNS",
            "length": len(packet),
        }

    def _handle_packet(self, packet: Any) -> None:
        try:
            dns_event = self._extract_dns_event(packet)
            if dns_event is None:
                return

            self.on_dns_event(dns_event)
        except Exception:
            # Ignore malformed packets to keep the stream running.
            return

    def start(self, interface: str, domain_filter: str = "") -> Dict[str, str]:
        if self.running:
            return {"status": "error", "message": "Capture is already running."}

        selected = self._resolve_selected_interface(interface)

        if selected is None:
            return {"status": "error", "message": "Selected interface not found."}

        capture_interface = selected.get("capture") or selected.get("name") or interface

        self.domain_filter = self._normalize_domain(domain_filter) if domain_filter else ""
        self.selected_interface = capture_interface

        try:
            self.sniffer = AsyncSniffer(
                iface=capture_interface,
                prn=self._handle_packet,
                store=False,
                promisc=True,
            )
            self.sniffer.start()
            self.running = True
            display_name = selected.get("display") or selected.get("name") or capture_interface
            return {"status": "ok", "message": f"Started capture on {display_name}"}
        except PermissionError:
            return {
                "status": "error",
                "message": "Permission denied. Run as Administrator/root.",
            }
        except socket.error as exc:
            return {"status": "error", "message": f"Socket error: {exc}"}
        except Exception as exc:
            return {"status": "error", "message": f"Failed to start capture: {exc}"}

    def stop(self) -> Dict[str, str]:
        if not self.running or self.sniffer is None:
            return {"status": "error", "message": "Capture is not running."}

        try:
            self.sniffer.stop()
            self.sniffer = None
            self.running = False
            self.selected_interface = None
            self.domain_filter = ""
            return {"status": "ok", "message": "Capture stopped."}
        except Exception as exc:
            return {"status": "error", "message": f"Failed to stop capture: {exc}"}

    def arp_scan(self, interface: str, timeout: int = 2) -> List[Dict[str, str]]:
        """Best-effort ARP scan in /24 network of selected interface."""
        selected = self._resolve_selected_interface(interface)
        if selected is None:
            raise ValueError("Selected interface not found.")

        capture_interface = selected.get("capture") or selected.get("name") or interface
        interface_ip = selected.get("ip", "")

        if not interface_ip or interface_ip in {"0.0.0.0", "N/A"}:
            raise ValueError("Selected interface has no valid IPv4 address.")

        network = ipaddress.ip_network(f"{interface_ip}/24", strict=False)
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = srp(arp_request, timeout=timeout, iface=capture_interface, verbose=False)

        devices = []
        seen = set()
        for _, response in answered:
            ip_addr = str(response.psrc)
            mac_addr = str(response.hwsrc)
            key = (ip_addr, mac_addr)
            if key in seen:
                continue
            seen.add(key)
            devices.append({"ip": ip_addr, "mac": mac_addr})

        return devices

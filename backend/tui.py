import argparse
import queue
import sys
import time
from collections import Counter, deque
from datetime import datetime
from typing import Any, Dict, List, Tuple

from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from sniffer import PacketSniffer


class DNSMonitorTUI:
    """Simple terminal UI for live DNS monitoring."""

    MAX_RECENT_ROWS = 25

    def __init__(self, interface: str = "", domain_filter: str = "") -> None:
        self.console = Console()
        self.sniffer = PacketSniffer(on_dns_event=self._on_dns_event)
        self.interface = interface
        self.domain_filter = domain_filter

        self.running = False
        self.selected_interface = ""
        self.selected_interface_label = ""
        self.status_message = "Idle"

        self._incoming_events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.recent_requests: deque[Dict[str, Any]] = deque(maxlen=self.MAX_RECENT_ROWS)
        self.device_counter: Counter[str] = Counter()
        self.domain_counter: Counter[str] = Counter()
        self.device_mac_map: Dict[str, str] = {}

    def _on_dns_event(self, event: Dict[str, Any]) -> None:
        event["timestamp"] = datetime.now().strftime("%H:%M:%S")
        self._incoming_events.put(event)

    def _drain_events(self) -> None:
        while True:
            try:
                event = self._incoming_events.get_nowait()
            except queue.Empty:
                return

            self.recent_requests.appendleft(event)

            device_ip = str(event.get("device_ip", ""))
            device_mac = str(event.get("device_mac", "Unknown"))
            domain = str(event.get("domain", ""))

            if device_ip:
                self.device_counter[device_ip] += 1
                if device_mac and device_mac != "Unknown":
                    self.device_mac_map[device_ip] = device_mac

            if domain:
                self.domain_counter[domain] += 1

    def _find_interface_label(self, capture_name: str) -> str:
        for item in self.sniffer.list_interfaces():
            if capture_name in {item.get("capture", ""), item.get("name", "")}:  # pragma: no branch
                return item.get("display", "") or item.get("name", "") or capture_name
        return capture_name

    def _pick_interface(self) -> Tuple[str, str]:
        interfaces = self.sniffer.list_interfaces()
        if not interfaces:
            raise RuntimeError("No network interfaces detected.")

        if self.interface:
            return self.interface, self._find_interface_label(self.interface)

        default_interface = self.sniffer.get_default_interface()
        default_label = self._find_interface_label(default_interface)

        table = Table(title="Available Interfaces", expand=True)
        table.add_column("#", justify="right")
        table.add_column("Display")
        table.add_column("Capture Name")
        table.add_column("IPv4")

        for index, item in enumerate(interfaces, start=1):
            table.add_row(
                str(index),
                item.get("display", ""),
                item.get("capture", "") or item.get("name", ""),
                item.get("ip", "N/A"),
            )

        self.console.print(table)
        prompt = (
            f"Select interface [1-{len(interfaces)}], "
            f"or press Enter for default ({default_label}): "
        )
        choice = self.console.input(prompt).strip()

        if not choice:
            return default_interface, default_label

        if not choice.isdigit():
            raise RuntimeError("Invalid selection. Please use a number.")

        selected_index = int(choice)
        if selected_index < 1 or selected_index > len(interfaces):
            raise RuntimeError("Selection out of range.")

        selected = interfaces[selected_index - 1]
        capture_name = selected.get("capture", "") or selected.get("name", "")
        label = selected.get("display", "") or selected.get("name", "") or capture_name
        return capture_name, label

    def _build_header(self) -> Panel:
        header = Table.grid(expand=True)
        header.add_column(justify="left")
        header.add_column(justify="right")

        state = "RUNNING" if self.running else "STOPPED"
        header.add_row("[bold cyan]Mini Wireshark DNS TUI[/bold cyan]", f"[bold]{state}[/bold]")
        header.add_row(f"Interface: {self.selected_interface_label}", f"Filter: {self.domain_filter or 'none'}")
        header.add_row("Stop with Ctrl+C", self.status_message)

        return Panel(header, border_style="cyan")

    def _build_devices_table(self) -> Panel:
        table = Table(title="Top Active Devices", expand=True)
        table.add_column("IP")
        table.add_column("MAC")
        table.add_column("Requests", justify="right")

        if not self.device_counter:
            table.add_row("-", "-", "0")
        else:
            for ip_addr, count in self.device_counter.most_common(8):
                table.add_row(ip_addr, self.device_mac_map.get(ip_addr, "Unknown"), str(count))

        return Panel(table, border_style="green")

    def _build_domains_table(self) -> Panel:
        table = Table(title="Popular Domains", expand=True)
        table.add_column("Domain")
        table.add_column("Count", justify="right")

        if not self.domain_counter:
            table.add_row("-", "0")
        else:
            for domain, count in self.domain_counter.most_common(8):
                table.add_row(domain, str(count))

        return Panel(table, border_style="magenta")

    def _build_requests_table(self) -> Panel:
        table = Table(title="Live DNS Requests", expand=True)
        table.add_column("Time", width=8)
        table.add_column("Device")
        table.add_column("Domain")
        table.add_column("Label")

        if not self.recent_requests:
            table.add_row("-", "-", "-", "-")
        else:
            for row in list(self.recent_requests):
                table.add_row(
                    str(row.get("timestamp", "-")),
                    str(row.get("device_ip", "-")),
                    str(row.get("domain", "-")),
                    str(row.get("readable_domain", "-")),
                )

        return Panel(table, border_style="blue")

    def _render(self) -> Group:
        top_row = Columns([self._build_devices_table(), self._build_domains_table()], equal=True, expand=True)
        return Group(self._build_header(), top_row, self._build_requests_table())

    def run(self) -> int:
        if not PacketSniffer.has_capture_permissions():
            self.console.print("[yellow]Warning: packet capture usually requires sudo/root privileges.[/yellow]")

        try:
            self.selected_interface, self.selected_interface_label = self._pick_interface()
        except Exception as exc:
            self.console.print(f"[red]Interface selection failed:[/red] {exc}")
            return 1

        start_result = self.sniffer.start(interface=self.selected_interface, domain_filter=self.domain_filter)
        if start_result.get("status") != "ok":
            self.console.print(f"[red]{start_result.get('message', 'Failed to start capture.')}[/red]")
            return 1

        self.running = True
        self.status_message = str(start_result.get("message", "Capture started."))

        self.console.print("[bold green]Capture started. Press Ctrl+C to stop.[/bold green]")

        try:
            with Live(self._render(), refresh_per_second=4, screen=True) as live:
                while self.running:
                    self._drain_events()
                    live.update(self._render())
                    time.sleep(0.2)
        except KeyboardInterrupt:
            self.status_message = "Stopping capture..."
        finally:
            stop_result = self.sniffer.stop()
            self.running = False
            message = stop_result.get("message", "Capture stopped.")
            self.console.print(f"\n[cyan]{message}[/cyan]")

        return 0


def print_interfaces(console: Console, interfaces: List[Dict[str, str]]) -> None:
    table = Table(title="Detected Interfaces", expand=True)
    table.add_column("Display")
    table.add_column("Capture Name")
    table.add_column("IPv4")

    for item in interfaces:
        table.add_row(
            item.get("display", ""),
            item.get("capture", "") or item.get("name", ""),
            item.get("ip", "N/A"),
        )

    console.print(table)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Terminal DNS monitor for Kali/Linux.")
    parser.add_argument("-i", "--interface", default="", help="Capture interface name.")
    parser.add_argument("-f", "--filter", default="", help="Only show domains containing this text.")
    parser.add_argument("--list-interfaces", action="store_true", help="Show interfaces and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    console = Console()

    if args.list_interfaces:
        interfaces = PacketSniffer.list_interfaces()
        if not interfaces:
            console.print("[red]No interfaces found.[/red]")
            return 1
        print_interfaces(console, interfaces)
        return 0

    app = DNSMonitorTUI(interface=args.interface, domain_filter=args.filter)
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
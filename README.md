# Mini Wireshark DNS Monitor (Educational)

An educational, advanced mini Wireshark-like tool that monitors DNS traffic in real time and maps:

- Device IP/MAC -> requested domain

Built with Python, Flask, Flask-SocketIO, Scapy, and a clean Web UI.

## Project Structure

backend/
  app.py
  sniffer.py
frontend/
  index.html
  style.css
  script.js
requirements.txt

## Features

- Live packet capture with Scapy on selected interface.
- Auto-selects default interface with Wi-Fi priority (Wi-Fi/Wireless/WLAN), fallback to first active.
- Promiscuous capture mode enabled.
- DNS query extraction in real time.
- Raw domain + readable service mapping in output.
- Device-wise traffic mapping:
  - Device IP
  - Device Name
  - Device MAC (when available)
  - Requested domain
- Connected devices table with request counters.
- Live DNS requests table.
- Domain filter (for capture and UI view).
- Device filter dropdown (show only selected device DNS requests).
- Popular domain highlighting.
- Top active devices ranking.
- Optional ARP scan for basic network mapping.
- Permission warning when not running as Administrator/root.
- HTTPS visibility note in UI.
- Debounced UI rendering for smoother live updates.

## Setup

1. Open terminal in project root.
2. Create virtual environment.
3. Install dependencies.

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

From project root (Windows PowerShell):

```powershell
.\.venv\Scripts\python .\backend\app.py
```

Then open:

http://localhost:5000

## Important Notes (Permissions)

- Packet sniffing usually requires elevated privileges.
- On Windows, run terminal as Administrator.
- On Linux/macOS, run with root/sudo as needed.
- Install Npcap on Windows and enable WinPcap compatibility mode.

## DNS Visibility Limitation

- HTTPS payloads are encrypted.
- This tool provides DNS/domain-level visibility, not full decrypted web content.

## Educational Scope

This project is a beginner-friendly network visibility tool for local traffic learning. It is not a full enterprise Wireshark replacement.

## Developer

reinF(Saugat Sapkota)

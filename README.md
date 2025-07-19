# Custom IPTables Firewall

A lightweight **Python + IPTables** solution for real-time packet inspection and dynamic rule creation. The script relies on **Scapy** for packet sniffing and the system’s `iptables`/`ip6tables` commands for rule management.

---

## Key Features

* **Initial hardening** – sets sensible default rules, rate-limits SYN floods, enables NAT masquerading, etc.
* **Dynamic blocking** – observes traffic and automatically drops packets from suspicious IP addresses or ports (defined in `blocked_ips` / `blocked_ports`).
* **IPv4 & IPv6 support** – applies equivalent rules for both stacks.
* **Extensible** – add custom logic in `packet_callback()` to react on any condition.

---

## Requirements

```bash
sudo apt install python3-scapy iptables iproute2
```

Python packages:
```bash
pip install scapy
```

> Root/`sudo` privileges are required to modify IPTables rules.

---

## Usage

```bash
sudo python3 firewall.py
```

* The script sets up baseline rules via `setup_iptables()`.
* Packets are sniffed with Scapy; matching traffic triggers `add_iptables_rule()` which inserts a drop rule in real time.
* Press **Ctrl+C** to terminate. Consider saving rules (`iptables-save`) if you want them to persist.

---

## File Overview

```
Custom IPTables Firewall.py   # Main script
README.md                    # Documentation
```

---

## Disclaimer

This project is for **educational purposes**. Misconfiguration of firewall rules can lock you out of systems. Use with caution!  
Licensed under the MIT License.

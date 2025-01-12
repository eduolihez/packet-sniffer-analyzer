import socket
import logging
from scapy.all import sniff, ARP, IP, Raw, get_if_list, get_if_addr, get_if_hwaddr, conf
from colorama import Fore, Style, init
from collections import defaultdict

# Initialize colorama for colored output
init(autoreset=True)

# Get the local IP address
local_ip = socket.gethostbyname(socket.gethostname())

# Initialize a dictionary to keep track of packet counts per IP (for DoS detection)
packet_counter = defaultdict(int)
threshold = 100  # Set threshold for DoS detection

# Configure logging
logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def list_interfaces():
    """List all available network interfaces with additional details."""
    print(f"{Fore.CYAN}Available network interfaces:{Style.RESET_ALL}")
    interfaces = get_if_list()
    for idx, interface in enumerate(interfaces):
        try:
            # Get IP and MAC address of the interface
            interface_ip = get_if_addr(interface)
            interface_mac = get_if_hwaddr(interface)
            # Determine if it's a Wi-Fi, Ethernet, or Virtual interface based on the interface name
            interface_type = "Wi-Fi" if "Wi-Fi" in interface else "Ethernet" if "Ethernet" in interface else "Virtual"
            print(f"{Fore.GREEN}[{idx}] {interface} - IP: {interface_ip} - MAC: {interface_mac} - Type: {interface_type}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to get details for {interface}: {e}{Style.RESET_ALL}")
    return interfaces

def detect_arp_spoof(packet):
    """Detect potential ARP spoofing attacks."""
    if packet.haslayer(ARP):
        if packet[ARP].op == 2:  # ARP Reply
            alert_msg = f"ARP Spoofing detected! Source IP: {packet[ARP].psrc}, Fake MAC: {packet[ARP].hwsrc}"
            print(f"{Fore.RED}[ALERT] {alert_msg}{Style.RESET_ALL}")
            logging.warning(alert_msg)

def detect_dos_attack(packet):
    """Detect potential DoS (Denial of Service) attacks."""
    if packet.haslayer(IP):
        ip_src = packet[IP].src

        # Ignore packets from the local machine
        if ip_src == local_ip:
            return

        # Track packet count for each source IP (Detect DoS behavior)
        packet_counter[ip_src] += 1

        # If a source IP exceeds the threshold, flag it as a potential DoS attack
        if packet_counter[ip_src] > threshold:
            alert_msg = f"Possible DoS attack detected from IP: {ip_src}"
            print(f"{Fore.RED}[ALERT] {alert_msg}{Style.RESET_ALL}")
            logging.warning(alert_msg)

def analyze_packet(packet):
    """Analyze captured packets."""
    try:
        # Detect potential sensitive data (e.g., passwords or login information)
        if packet.haslayer(Raw):  # Check for raw data
            raw_data = packet[Raw].load.decode(errors='ignore')
            if "password" in raw_data or "login" in raw_data:
                info_msg = f"Potential sensitive data detected: {raw_data}"
                print(f"{Fore.YELLOW}[INFO] {info_msg}{Style.RESET_ALL}")
                logging.info(info_msg)

        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            info_msg = f"Packet: {ip_src} -> {ip_dst}"
            print(f"{Fore.CYAN}[INFO] {info_msg}{Style.RESET_ALL}")
            logging.info(info_msg)

        # Detect ARP spoofing and DoS attacks
        detect_arp_spoof(packet)
        detect_dos_attack(packet)

    except Exception as e:
        error_msg = f"Failed to process packet: {e}"
        print(f"{Fore.RED}[ERROR] {error_msg}{Style.RESET_ALL}")
        logging.error(error_msg)

def capture_packets(interface):
    """Capture packets on a specified network interface."""
    print(f"{Fore.GREEN}Starting packet sniffer on interface: {interface}{Style.RESET_ALL}")
    try:
        sniff(iface=interface, prn=analyze_packet, store=False)
    except PermissionError:
        error_msg = "[ERROR] Permission denied. Try running as administrator/root."
        print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
        logging.error(error_msg)
    except Exception as e:
        error_msg = f"[ERROR] Failed to start sniffer: {e}"
        print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
        logging.error(error_msg)

def main():
    print(f"{Fore.CYAN}Packet Sniffer - Starting...{Style.RESET_ALL}")
    
    # List available interfaces
    interfaces = list_interfaces()
    
    # Prompt user to select an interface
    try:
        interface_idx = int(input(f"{Fore.YELLOW}Select the interface number to sniff: {Style.RESET_ALL}"))
        if interface_idx < 0 or interface_idx >= len(interfaces):
            print(f"{Fore.RED}Invalid selection. Please restart the program.{Style.RESET_ALL}")
            return
        selected_interface = interfaces[interface_idx]
        print(f"{Fore.GREEN}You selected: {selected_interface}{Style.RESET_ALL}")
        capture_packets(selected_interface)
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a valid number.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        logging.error(f"Error: {e}")

if __name__ == "__main__":
    main()

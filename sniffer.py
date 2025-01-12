from scapy.all import sniff, ARP, IP, Raw, TCP, get_if_list, get_if_addr
from scapy.layers.dot11 import Dot11, Dot11Beacon
from collections import defaultdict
from colorama import Fore, Style, init
import logging

# Initialize colorama for colored output
init(autoreset=True)

# Setup logging
logging.basicConfig(filename="network_events.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Global variables for tracking
arp_table = {}
ip_count = defaultdict(int)
port_scan_count = defaultdict(int)

def list_interfaces():
    """List all available network interfaces with descriptions."""
    print(f"{Fore.CYAN}Available network interfaces:{Style.RESET_ALL}")
    interfaces = get_if_list()
    
    for idx, interface in enumerate(interfaces):
        # Try to get an IP address for the interface
        try:
            ip_address = get_if_addr(interface)
        except:
            ip_address = "N/A"
        
        # Classify interface type
        if "Wi-Fi" in interface or "wlan" in interface.lower():
            interface_type = "Wi-Fi"
        elif "Ethernet" in interface or "eth" in interface.lower():
            interface_type = "Ethernet"
        elif "Loopback" in interface or "lo" in interface.lower():
            interface_type = "Loopback"
        else:
            interface_type = "Virtual or Unknown"
        
        print(f"{Fore.GREEN}[{idx}] {interface} ({interface_type}) - IP: {ip_address}{Style.RESET_ALL}")
    
    return interfaces

def detect_arp_spoof(packet):
    """Detect ARP spoofing attacks by comparing MAC addresses."""
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        ip_src = packet[ARP].psrc
        mac_src = packet[ARP].hwsrc
        
        if ip_src in arp_table:
            if arp_table[ip_src] != mac_src:
                print(f"{Fore.RED}[ALERT] ARP Spoofing detected! IP: {ip_src}, Fake MAC: {mac_src}{Style.RESET_ALL}")
                log_event(f"ARP Spoofing detected! IP: {ip_src}, Fake MAC: {mac_src}")
        else:
            arp_table[ip_src] = mac_src

def detect_dos(packet):
    """Detect potential Denial of Service (DoS) attacks."""
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_count[ip_src] += 1
        if ip_count[ip_src] > 100:  # Threshold can be adjusted
            print(f"{Fore.RED}[ALERT] Possible DoS attack detected from {ip_src}{Style.RESET_ALL}")
            log_event(f"Possible DoS attack detected from {ip_src}")

def detect_port_scanning(packet):
    """Detect potential port scanning attempts."""
    if packet.haslayer(TCP) and packet[TCP].flags == "S":  # TCP SYN packet
        ip_dst = packet[IP].dst
        port_dst = packet[TCP].dport
        port_scan_count[ip_dst] += 1
        if port_scan_count[ip_dst] > 5:  # Threshold can be adjusted
            print(f"{Fore.RED}[ALERT] Possible port scanning detected on {ip_dst} targeting port {port_dst}{Style.RESET_ALL}")
            log_event(f"Possible port scanning detected on {ip_dst} targeting port {port_dst}")

def detect_open_network(packet):
    """Detect open Wi-Fi networks (no encryption)."""
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11].info.decode(errors='ignore')
        encryption = packet[Dot11Beacon].capabilities
        if 'privacy' not in encryption:  # If 'privacy' is not in capabilities, it's open
            print(f"{Fore.YELLOW}[INFO] Open Wi-Fi network detected: {ssid}{Style.RESET_ALL}")
            log_event(f"Open Wi-Fi network detected: {ssid}")

def detect_http_https(packet):
    """Detect potential sensitive data in HTTP/HTTPS traffic."""
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode(errors='ignore')
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if "HTTP" in raw_data:
                if "password" in raw_data or "username" in raw_data:
                    print(f"{Fore.YELLOW}[INFO] Potential sensitive data in HTTP traffic: {raw_data} from {ip_src} -> {ip_dst}{Style.RESET_ALL}")
                    log_event(f"Potential sensitive data in HTTP traffic: {raw_data} from {ip_src} -> {ip_dst}")

def analyze_packet(packet):
    """Analyze captured packets."""
    try:
        # Detect sensitive data in HTTP/HTTPS traffic
        detect_http_https(packet)

        # Detect Denial of Service (DoS) attacks
        detect_dos(packet)

        # Detect port scanning
        detect_port_scanning(packet)

        # Detect ARP spoofing
        detect_arp_spoof(packet)

        # Detect open Wi-Fi networks
        detect_open_network(packet)
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to process packet: {e}{Style.RESET_ALL}")

def capture_packets(interface):
    """Capture packets on a specified network interface."""
    print(f"{Fore.GREEN}Starting packet sniffer on interface: {interface}{Style.RESET_ALL}")
    try:
        sniff(iface=interface, prn=analyze_packet, store=False)
    except PermissionError:
        print(f"{Fore.RED}[ERROR] Permission denied. Try running as administrator/root.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to start sniffer: {e}{Style.RESET_ALL}")

def log_event(event_message):
    """Log event to a file."""
    logging.info(event_message)

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

if __name__ == "__main__":
    main()

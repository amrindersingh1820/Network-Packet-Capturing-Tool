import os
import logging
import socket
import threading
import datetime
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff, srp
import netifaces

# Logger configuration
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

packet_data = []
network_devices = {}

def get_active_network_interface():
    """Detect the active internet-connected network interface."""
    gateways = netifaces.gateways()
    default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)

    if default_gateway:
        return default_gateway[1]  # Returns the interface used for internet access

    logger.error("❌ No active internet-connected interface found!")
    exit(1)

def get_local_network():
    """Determine the local network's IP range."""
    interface = get_active_network_interface()
    addrs = netifaces.ifaddresses(interface)

    if netifaces.AF_INET in addrs:
        ip_info = addrs[netifaces.AF_INET][0]
        ip_address = ip_info["addr"]
        netmask = ip_info["netmask"]

        # Convert netmask to CIDR notation
        cidr = sum(bin(int(x)).count("1") for x in netmask.split("."))
        return f"{ip_address}/{cidr}"

    logger.error("❌ Unable to determine local network range!")
    exit(1)

def get_mac(ip):
    """Retrieve the MAC address of a device on the local network."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=1, verbose=False)

    for _, received in answered:
        return received.hwsrc  # Return MAC address if found
    return None  # MAC address not found

def get_device_name(mac):
    """Identify device manufacturer based on MAC address."""
    if mac in network_devices:
        return network_devices[mac]

    vendor_dict = {
        "70:97:41": "Arcadyan Corporation",
        "C6:55:6E": "Apple iPhone 13",
        "7E:3B:19": "Unknown Device",
    }
    manufacturer = vendor_dict.get(mac[:8].upper(), "Unknown Device")
    network_devices[mac] = manufacturer  # Cache the result
    return manufacturer

def resolve_hostname(ip):
    """Resolve an IP address to a hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_network():
    """Scan the network for connected devices."""
    network_ip = get_local_network()
    logger.info(f"🔍 Scanning network {network_ip}...")

    arp_request = ARP(pdst=network_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=2, verbose=False)

    logger.info("\n📡 Connected Devices:")
    logger.info(f"{'IP Address':<18}{'MAC Address':<20}{'Device'}")

    for sent, received in answered:
        mac = received.hwsrc
        device = get_device_name(mac)
        network_devices[mac] = device
        logger.info(f"{received.psrc:<18}{mac:<20}{device}")

def packet_callback(packet):
    """Process captured packets."""
    if IP not in packet:
        return  # Ignore non-IP packets

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(packet[IP].proto, f"Unknown({packet[IP].proto})")
    size = len(packet)
    dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
    hostname = resolve_hostname(dst_ip)

    mac_address = get_mac(src_ip)  # Get MAC address of source IP
    device_name = get_device_name(mac_address) if mac_address else "Unknown Device"

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    packet_info = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "hostname": hostname,
        "protocol": protocol,
        "size": size,
        "dst_port": dst_port,
        "device": device_name,
    }

    packet_data.append(packet_info)

    log_message = (
        f"[{timestamp}] 🔗 Packet {len(packet_data)}: {src_ip} -> {dst_ip} ({hostname}) | "
        f"Protocol: {protocol} | Port: {dst_port} | Device: {device_name}"
    )

    logger.info(log_message)

def sniff_packets():
    """Start live packet sniffing."""
    interface = get_active_network_interface()
    logger.info(f"🔍 Capturing packets on interface {interface}... Press 'X' and hit ENTER to stop.\n")

    stop_sniffing = threading.Event()

    def sniffing():
        sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda x: stop_sniffing.is_set())

    thread = threading.Thread(target=sniffing)
    thread.start()

    while True:
        user_input = input().strip().lower()
        if user_input == 'x':
            stop_sniffing.set()
            break

    logger.info("\n🛑 Capture stopped by user.\n")
    show_packet_details()

def show_packet_details():
    """Display details of captured packets."""
    while True:
        user_input = input("\nEnter packet number for details (or 'q' to quit): ").strip()
        if user_input.lower() == 'q':
            break

        try:
            packet_number = int(user_input)
            if 1 <= packet_number <= len(packet_data):
                packet = packet_data[packet_number - 1]
                logger.info("\n📜 Packet Details:")
                logger.info(f"Time: {packet['timestamp']}")
                logger.info(f"Frame {packet_number}: {packet['size']} bytes captured")
                logger.info(f"Source: {packet['src_ip']} ({packet['device']})")
                logger.info(f"Destination: {packet['dst_ip']} ({packet['hostname']})")
                logger.info(f"Protocol: {packet['protocol']}")
                logger.info(f"Port: {packet['dst_port']}")
            else:
                logger.warning("⚠️ Invalid packet number!")
        except ValueError:
            logger.warning("⚠️ Please enter a valid number!")

if __name__ == "__main__":
    scan_network()
    sniff_packets()
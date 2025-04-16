import sys
import os
import logging
import socket
import datetime
import threading
import csv
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff, srp
import netifaces
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit,
    QTableWidget, QTableWidgetItem, QFileDialog, QLineEdit, QHBoxLayout
)
from PyQt6.QtCore import QTimer, Qt

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

packet_data = []
network_devices = {}
sniffing_active = False


def get_active_network_interface():
    """Find the active network interface used for the internet connection."""
    gateways = netifaces.gateways()
    default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)
    if default_gateway:
        return default_gateway[1]
    logger.error("❌ No active internet-connected interface found!")
    return None


def get_local_network():
    """Retrieve the local network's IP and CIDR."""
    interface = get_active_network_interface()
    if not interface:
        return None
    addrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in addrs:
        ip_info = addrs[netifaces.AF_INET][0]
        ip_address = ip_info["addr"]
        netmask = ip_info["netmask"]
        cidr = sum(bin(int(x)).count("1") for x in netmask.split("."))
        return f"{ip_address}/{cidr}"
    return None


def scan_network():
    """Scan the local network for connected devices."""
    network_ip = get_local_network()
    if not network_ip:
        return []
    logger.info(f"🔍 Scanning network {network_ip}...")
    arp_request = ARP(pdst=network_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=2, verbose=False)

    devices = []
    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        device = get_device_name(mac)
        devices.append((ip, mac, device))
        network_devices[mac] = device
    return devices


def get_mac(ip):
    """Get the MAC address of a given IP."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=1, verbose=False)
    for _, received in answered:
        return received.hwsrc
    return None


def get_device_name(mac):
    """Retrieve the device name from the MAC address."""
    return network_devices.get(mac, "Unknown Device")


def resolve_hostname(ip):
    """Resolve an IP address to a hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def packet_callback(packet):
    """Process incoming packets and store relevant information."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(packet[IP].proto, f"Unknown({packet[IP].proto})")
        size = len(packet)
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
        hostname = resolve_hostname(dst_ip)
        mac_address = get_mac(src_ip)
        device_name = get_device_name(mac_address) if mac_address else "Unknown Device"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_info = [timestamp, src_ip, dst_ip, hostname, protocol, size, dst_port, device_name]
        packet_data.append(packet_info)


def sniff_packets():
    """Sniff network packets continuously."""
    global sniffing_active
    interface = get_active_network_interface()
    if not interface:
        return
    sniffing_active = True
    try:
        sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda x: not sniffing_active)
    except PermissionError:
        logger.error("Permission denied. Try running with sudo.")
    except Exception as e:
        logger.error(f"Error: {e}")


class NetworkTrafficAnalyzer(QWidget):
    """GUI Application for Network Traffic Analysis."""

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        """Initialize the user interface."""
        self.setWindowTitle("Network Traffic Analyzer")
        self.setGeometry(100, 100, 900, 600)
        layout = QVBoxLayout()

        # Filter bar like Wireshark
        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter expression (e.g., TCP, UDP, IP)")
        self.apply_filter_button = QPushButton("Apply Filter")
        self.apply_filter_button.clicked.connect(self.applyFilter)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.apply_filter_button)
        layout.addLayout(filter_layout)

        self.scanButton = QPushButton("Scan Network")
        self.scanButton.clicked.connect(self.scanNetwork)
        layout.addWidget(self.scanButton)

        self.startButton = QPushButton("Start Sniffing")
        self.startButton.clicked.connect(self.startSniffing)
        layout.addWidget(self.startButton)

        self.stopButton = QPushButton("Stop Sniffing")
        self.stopButton.clicked.connect(self.stopSniffing)
        layout.addWidget(self.stopButton)

        self.exportButton = QPushButton("Export to CSV")
        self.exportButton.clicked.connect(self.exportToCSV)
        layout.addWidget(self.exportButton)

        self.logOutput = QTextEdit()
        self.logOutput.setReadOnly(True)
        layout.addWidget(self.logOutput)

        self.packetTable = QTableWidget()
        self.packetTable.setColumnCount(8)
        self.packetTable.setHorizontalHeaderLabels(
            ["Timestamp", "Src IP", "Dst IP", "Hostname", "Protocol", "Size", "Dst Port", "Device"])
        layout.addWidget(self.packetTable)

        self.setLayout(layout)

    def scanNetwork(self):
        """Scan the network and display results."""
        devices = scan_network()
        self.logOutput.append("📡 Connected Devices:")
        for ip, mac, device in devices:
            self.logOutput.append(f"{ip} - {mac} - {device}")

    def startSniffing(self):
        """Start capturing packets in a separate thread."""
        self.logOutput.append("🔍 Capturing packets...")
        self.sniffThread = threading.Thread(target=sniff_packets, daemon=True)
        self.sniffThread.start()
        QTimer.singleShot(2000, self.updatePacketTable)

    def stopSniffing(self):
        """Stop the packet sniffing."""
        global sniffing_active
        sniffing_active = False
        self.logOutput.append("🛑 Capture stopped.")

    def updatePacketTable(self):
        """Update the GUI table with captured packets."""
        self.packetTable.setRowCount(len(packet_data))
        for row, packet in enumerate(packet_data):
            for col, data in enumerate(packet):
                self.packetTable.setItem(row, col, QTableWidgetItem(str(data)))

    def applyFilter(self):
        """Apply a user-defined filter (currently just logs it)."""
        filter_text = self.filter_input.text().strip()
        if filter_text:
            self.logOutput.append(f"Applying filter: {filter_text}")

    def exportToCSV(self):
        """Export captured packets to a CSV file."""
        filename, _ = QFileDialog.getSaveFileName(self, "Save File", "packets.csv", "CSV Files (*.csv)")
        if filename:
            with open(filename, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Src IP", "Dst IP", "Hostname", "Protocol", "Size", "Dst Port", "Device"])
                writer.writerows(packet_data)
            self.logOutput.append(f"✅ Data exported to {filename}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkTrafficAnalyzer()
    window.show()
    sys.exit(app.exec())
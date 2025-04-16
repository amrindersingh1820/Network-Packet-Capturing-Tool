# Network Traffic Analyzer

## Overview

This is a Network Traffic Analyzer that allows users to monitor network packets, scan connected devices, and analyze traffic using both a GUI and a command-line interface (CLI).

## Features

- Capture and analyze network packets
- Scan connected devices on the local network
- Export captured data to CSV
- Apply filters for specific protocols (TCP, UDP, ICMP, etc.)
- GUI built with PyQt6 for an enhanced user experience
- CLI mode for quick and lightweight analysis

## Requirements

Ensure you have Python 3 installed on your system.

### Install Dependencies

Run the following command to install the required dependencies:

```sh
pip install -r requirements.txt
```

## Running the Program

### GUI Mode

To launch the graphical user interface:

```sh
python live_packet_analyzer(GUI).py
```

### CLI Mode

To run the command-line interface:

```sh
python live_packet_analyzer(CMLI).py
```

## Usage Instructions

### GUI Interface

1. Click on `Scan Network` to detect connected devices.
2. Click `Start Sniffing` to begin capturing network packets.
3. Click `Stop Sniffing` to halt packet capture.
4. Use the `Filter` input box to apply protocol filters.
5. Click `Export to CSV` to save captured data.

### CLI Interface

1. Run the script using `python network_cli.py`.
2. It will automatically start sniffing packets.
3. Press `Ctrl + C` to stop packet capture.
4. Use optional command-line arguments for specific filtering.

## Notes

- This program requires administrator/root privileges to capture network packets.
- Ensure your firewall/antivirus does not block packet sniffing.

## License

This project is licensed under the MIT License.

## Author

Developed by Amrinder Singh




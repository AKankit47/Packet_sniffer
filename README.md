
# Packet Sniffer Tool

This is a Python-based packet sniffer tool designed for educational purposes. It captures and analyzes network packets, displaying essential details such as source and destination IP addresses, protocols, and payload data.

## Features
- Captures live network traffic.
- Extracts key information from packets:
  - Source and Destination IP addresses.
  - Protocols (TCP, UDP, ICMP, etc.).
  - Packet payload data.
- Filters for IP-based packets.
- Lightweight and simple to use.

## Requirements
- Python 3.6+
- Administrative/root privileges (required for capturing network traffic).
- Libraries:
  - [scapy](https://scapy.net/): Install it using `pip install scapy`.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/AKankit47/Packet_sniffer.git
   cd Prodigy_7_task5
   ```
2. Install dependencies:
   ```bash
   pip install scapy
   ```

## Usage
1. Run the script with administrative/root privileges:
   ```bash
   sudo python3 task5.py
   ```
2. Observe the captured packets in real-time.
3. Stop the sniffer using `Ctrl+C`.

## Output Example
When packets are captured, details are displayed:
```
[+] Packet Captured:
    Source IP: 192.168.1.2
    Destination IP: 192.168.1.1
    Protocol: TCP
    Payload: b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
```

## Notes
- This tool is intended for educational and authorized use only. Ensure you have proper authorization before monitoring any network.
- Use responsibly and ethically, adhering to all applicable laws and regulations.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
- [Scapy Documentation](https://scapy.readthedocs.io/) for providing an excellent library for packet manipulation.

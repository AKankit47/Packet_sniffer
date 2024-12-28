from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = packet[IP].payload

        # Determine the protocol
        if proto == 6:  # TCP
            protocol = "TCP"
        elif proto == 17:  # UDP
            protocol = "UDP"
        elif proto == 1:  # ICMP
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Print captured packet details
        print(f"\n[+] Packet Captured:")
        print(f"    Source IP: {src_ip}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Protocol: {protocol}")
        print(f"    Payload: {str(payload)}")


def main():
    print("Starting Packet Sniffer...")
    print("Press Ctrl+C to stop.")

    # Start sniffing (filter for IP traffic)
    try:
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nStopping Packet Sniffer.")


if __name__ == "__main__":
    main()

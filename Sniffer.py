from scapy.all import sniff, IP, TCP, UDP

def packet_analyzer(packet):
    # Check if packet has IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\n==============================")
        print("Source IP:", src_ip)
        print("Destination IP:", dest_ip)

        # Check protocol
        if packet.haslayer(TCP):
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        else:
            print("Protocol: Other")

        # Display payload
        if packet.haslayer(TCP) and packet[TCP].payload:
            print("Payload:", packet[TCP].payload)

print("Starting Network Sniffer...")
sniff(prn=packet_analyzer, count=10)
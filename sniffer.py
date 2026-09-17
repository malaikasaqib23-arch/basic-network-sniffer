from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw


packet_count = 0


def show_text_payload(payload):
    try:
        text = payload.decode("utf-8", errors="replace")
        text = text.replace("\r", " ").replace("\n", " ").strip()

        if not text:
            return

        printable_count = sum(c.isprintable() for c in text)
        printable_ratio = printable_count / len(text)

        if printable_ratio >= 0.7:
            print(f"Payload          : {text[:100]}")
        else:
            print("Payload          : Raw Binary Data")

    except Exception:
        print("Payload          : Raw Binary Data")


def process_packet(packet):
    global packet_count

    # Ignore packets that do not contain IPv4
    if not packet.haslayer(IP):
        return

    packet_count += 1

    ip = packet[IP]

    print("\n" + "=" * 60)
    print(f"PACKET #{packet_count}")
    print("=" * 60)

    print(f"Source IP        : {ip.src}")
    print(f"Destination IP   : {ip.dst}")

    # ---------------- TCP ----------------

    if packet.haslayer(TCP):

        tcp = packet[TCP]

        print("Protocol         : TCP")
        print(f"Source Port      : {tcp.sport}")
        print(f"Destination Port : {tcp.dport}")

        # HTTPS / TLS traffic
        if tcp.sport == 443 or tcp.dport == 443:

            print("Payload          : Encrypted HTTPS/TLS Data")

        # Other TCP traffic
        elif packet.haslayer(Raw):

            payload = packet[Raw].load

            if payload:
                show_text_payload(payload)

    # ---------------- UDP ----------------

    elif packet.haslayer(UDP):

        udp = packet[UDP]

        print("Protocol         : UDP")
        print(f"Source Port      : {udp.sport}")
        print(f"Destination Port : {udp.dport}")

        # QUIC / HTTP3 traffic
        if udp.sport == 443 or udp.dport == 443:

            print("Payload          : Encrypted QUIC/HTTP3 Data")

        # Other UDP traffic
        elif packet.haslayer(Raw):

            payload = packet[Raw].load

            if payload:
                show_text_payload(payload)

    # ---------------- ICMP ----------------

    elif packet.haslayer(ICMP):

        print("Protocol         : ICMP")

    # ---------------- Other ----------------

    else:

        print("Protocol         : Other")

    print("=" * 60)


# ---------------- PROGRAM START ----------------

print("=" * 60)
print("              BASIC NETWORK SNIFFER")
print("=" * 60)
print("Interface : Intel(R) Wireless-AC 9560 160MHz")
print("Status    : Capturing packets...")
print("Press Ctrl + C to stop.")
print("=" * 60)


sniff(
    iface="Intel(R) Wireless-AC 9560 160MHz",
    prn=process_packet,
    store=False
)
from scapy.all import sniff
import matplotlib.pyplot as plt

protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Others": 0}

def process_packet(packet):
    if packet.haslayer("TCP"):
        protocol_count["TCP"] += 1
    elif packet.haslayer("UDP"):
        
        protocol_count["UDP"] += 1
    elif packet.haslayer("ICMP"):
        protocol_count["ICMP"] += 1
    else:
        protocol_count["Others"] += 1

print("Sniffing packets... Please wait.")
packets = sniff(count=50, prn=process_packet)

print("\nPacket Count by Protocol:")
for proto, count in protocol_count.items():
    print(f"{proto}: {count}")

plt.bar(protocol_count.keys(), protocol_count.values(), color=["blue", "green", "red", "gray"])
plt.xlabel("Protocol")
plt.ylabel("Packet Count")
plt.title("Network Packet Distribution")
plt.show()

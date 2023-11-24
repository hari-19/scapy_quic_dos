from scapy.all import rdpcap, IP, UDP, Raw, send

dst = "10.240.0.120"

ip = "127.0.0.2" 
port = 20000
if __name__ == '__main__':
    pcap = rdpcap('quic_data.pcap')

    for i in range(0, 65535) :
        if port == 65535 :
            port = 20000
            ip = "127.0.0.3" 
        pkt = pcap[i%len(pcap)]
        quic_bytes = bytes(pkt["UDP"])[8:]
        quic_packet = IP(src=ip, dst=dst)/UDP(sport=443, dport=port)/Raw(load=quic_bytes)
        send(quic_packet, verbose=True)
        port+=1

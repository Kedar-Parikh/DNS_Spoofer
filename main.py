import netfilterqueue as nfq
import scapy.all as scapy

def processpacket(packet):
    spacket = scapy.IP(packet.get_payload())
    print(spacket.show())
    packet.accept()
try:
    queue = nfq.NetfilterQueue()
    queue.bind(0, processpacket)
    queue.run()
except KeyboardInterrupt:
    print("Quitting...")
    exit(0)

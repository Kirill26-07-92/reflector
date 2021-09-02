#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

victimIp = ''
victimMac = ''
reflectorIp = ''
reflectorMac = ''
interface = ''


def send_arp_response(incoming_packet):
    if incoming_packet[ARP].pdst != victimIp and incoming_packet[ARP].pdst != reflectorIp:
        return

    arp_victim_packet = ARP(psrc=victimIp,
                            pdst=incoming_packet[ARP].psrc,
                            op=ARP.is_at,
                            hwsrc=victimMac,
                            hwdst='ff:ff:ff:ff:ff:ff')
    send(arp_victim_packet)

    arp_reflector_packet = ARP(psrc=reflectorIp,
                               pdst=incoming_packet[ARP].psrc,
                               op=ARP.is_at,
                               hwsrc=reflectorMac,
                               hwdst='ff:ff:ff:ff:ff:ff')
    send(arp_reflector_packet)


def send_ip_response(incoming_packet):
    ip_packet = incoming_packet.getlayer(IP)

    if incoming_packet[IP].dst == victimIp:
        arp_packet = ARP(psrc=reflectorIp, pdst=incoming_packet[IP].src, op=1)
        send(arp_packet)

        ip_packet[IP].dst, ip_packet[IP].src = incoming_packet[IP].src, reflectorIp
        del ip_packet[IP].chksum

        if TCP in ip_packet:
            del ip_packet[TCP].chksum

        if UDP in ip_packet:
            del ip_packet[UDP].chksum

        send(ip_packet)

    if incoming_packet[IP].dst == reflectorIp:
        arp_packet = ARP(psrc=victimIp, pdst=incoming_packet[IP].src, op=1)
        send(arp_packet)

        ip_packet[IP].dst, ip_packet[IP].src = incoming_packet[IP].src, victimIp
        del ip_packet[IP].chksum

        if TCP in ip_packet:
            del ip_packet[TCP].chksum

        if UDP in ip_packet:
            del ip_packet[UDP].chksum
        send(ip_packet)


def call_back(incoming_packet):
    if ARP in incoming_packet:
        send_arp_response(incoming_packet)

    if IP in incoming_packet:
        send_ip_response(incoming_packet)


def main():
    sniff(iface=interface, prn=call_back, store=0, count=0)


params = {}
for i in range(0, 5):
    params[sys.argv[2 * i + 1]] = sys.argv[2 * i + 2]

print(params)

victimIp = params['--victim-ip']
victimMac = params['--victim-ethernet']
reflectorIp = params['--reflector-ip']
reflectorMac = params['--reflector-ethernet']
interface = params['--interface']
main()

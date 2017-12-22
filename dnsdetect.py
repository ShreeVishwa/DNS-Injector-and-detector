import argparse
import os
import sys
from scapy.all import *
import logging
import netifaces
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def parse():
	parser = argparse.ArgumentParser(add_help=False, description="DNS injection tool")
	parser.add_argument("-i", help="Name of the interface to capture the packet")
	parser.add_argument("-r", help="Pcap trace file to read from")
	parser.add_argument("expression", nargs="*", action="store")
	parser.add_argument('-ip','-?','--ip','-help','--help',action="store_true", help=argparse.SUPPRESS)
	args = parser.parse_args()
	if args.ip:
		parser.print_help()
		sys.exit()
	return args.i, args.r, args.expression

def sniff_pkt(pkt_captured):
	def dnsdetect(pkt):
		flag = 0
		if pkt.haslayer(DNSRR) and pkt.haslayer(UDP):
			# print("Its a response object")
		# print(pkt[DNS].qr)
			if pkt[DNS].qr:
				if len(expression) == 0:
		# print("Entered DNS qr")
					if len(pkt_captured) > 0:
			# print(len(pkt_captured))
						for i in range(len(pkt_captured)):
							if pkt_captured[i][IP].dst == pkt[IP].dst:
								# print("Yes dst ips same")
								if pkt_captured[i][UDP].sport == pkt[UDP].sport and pkt_captured[i][UDP].dport == pkt[UDP].dport:
									# print("Yes ports are same")
									# print(pkt_captured[i][DNS].id)
									# print(pkt[DNS].id)
									# print(pkt_captured[i][DNSRR].rdata)
									# print(pkt[DNSRR].rdata)
									if pkt_captured[i][DNS].id == pkt[DNS].id and pkt_captured[i][DNSRR].rdata != pkt[DNSRR].rdata:
										pkts1 = []
										pkts2 = []
										print(pkt_captured[i][DNS].ancount)
										for j in range(int(pkt_captured[i][DNS].ancount)):
											if type(pkt_captured[i][DNS].an[j].rdata) == str:
												pkts1.append(pkt_captured[i][DNS].an[j].rdata)
											else:
												pkts1.append(pkt_captured[i][DNS].an[j].rdata.decode("utf-8"))
										for j in range(int(pkt[DNS].ancount)):
											if type(pkt[DNS].an[j].rdata) == str:
												pkts2.append(pkt[DNS].an[j].rdata)
											else:
												pkts2.append(pkt[DNS].an[j].rdata.decode("utf-8"))
										for p in pkts1:
											if p in pkts2:
												flag = 1
										if flag:
											continue
										print("DNS poisioning attempt")
										print("TXID " + str(pkt[DNS].id) + " Request " + pkt[DNSQR].qname[:-1].decode("utf-8"))
										print("Answer1 " + str(pkts1))
										print("Answer2 " + str(pkts2))
					pkt_captured.append(pkt)
			# print(len(pkt_captured))
			# print(pkt[DNS].id)
					if len(pkt_captured) > 30:
						pkt_captured.remove(pkt_captured[0])

				else:
					if pkt[IP].src in expression:
						if len(pkt_captured) > 0:
				# print(len(pkt_captured))
							for i in range(len(pkt_captured)):
								if pkt_captured[i][IP].dst == pkt[IP].dst:
									# print("Yes dst ips same")
									if pkt_captured[i][UDP].sport == pkt[UDP].sport and pkt_captured[i][UDP].dport == pkt[UDP].dport:
										# print("Yes ports are same")
										# print(pkt_captured[i][DNS].id)
										# print(pkt[DNS].id)
										# print(pkt_captured[i][DNSRR].rdata)
										# print(pkt[DNSRR].rdata)
										if pkt_captured[i][DNS].id == pkt[DNS].id and pkt_captured[i][DNSRR].rdata != pkt[DNSRR].rdata and pkt_captured[i][IP].payload != pkt[IP].payload:
											print("DNS poisioning attempt")
											print("TXID " + str(pkt[DNS].id) + " Request " + pkt[DNSQR].qname[:-1].decode("utf-8"))
											pkts1 = []
											pkts2 = []
											print(pkt_captured[i][DNS].ancount)
											for j in range(int(pkt_captured[i][DNS].ancount)):
												if type(pkt_captured[i][DNS].an[j].rdata) == str:
													pkts1.append(pkt_captured[i][DNS].an[j].rdata)
												else:
													pkts1.append(pkt_captured[i][DNS].an[j].rdata.decode("utf-8"))
											for j in range(int(pkt[DNS].ancount)):
												if type(pkt[DNS].an[j].rdata) == str:
													pkts2.append(pkt[DNS].an[j].rdata)
												else:
													pkts2.append(pkt[DNS].an[j].rdata.decode("utf-8"))
											print("Answer1 " + str(pkts1))
											print("Answer2 " + str(pkts2))
						pkt_captured.append(pkt)
				# print(len(pkt_captured))
				# print(pkt[DNS].id)
						if len(pkt_captured) > 30:
							pkt_captured.remove(pkt_captured[0])

	return dnsdetect

if __name__ == '__main__':
	interface, trace_file ,expression = parse()
	try:
		pkt_captured = []
	# if expression:
	# 	print("Monitoring on Ip's " + " ".join(expression))
		if trace_file:
			print("Checking for the poisoning attacks in provided trace file")
			sniff(filter='udp port 53', offline=trace_file, store=0, prn=sniff_pkt(pkt_captured))
		if interface:
			print(interface)
			sniff(filter='udp port 53', iface=interface, store=0, prn=sniff_pkt(pkt_captured))
		else:
			print("Capture on all interfaces")
			default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
			sniff(filter='udp port 53', iface = default_interface, store=0, prn=sniff_pkt(pkt_captured))
	except AttributeError:
		os.system('clear')
		print("Invalid entry/entries")
		print("dnsdetect [-i interface] [-r tracefile] expression")

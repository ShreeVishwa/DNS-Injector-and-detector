Note: This program has been implemented using python3 and scapy library

Versions of softwares used:
	- Ubuntu 16.04
	- python 3.5
	- netifaces installed using pip
	- scapy version installed from the github link https://github.com/secdev/scapy

Implementation:

- Dnsinject:
	If the interface to be sniffed is provided then the provided interface is sniffed else the 		default interface would be selected by the netifaces module and the sniffing would be 		performed on the default interface. After sniffing if the hostname file is provided then 		the packets would be sniffed accordingly by parsing the hostnames file and a forged 		response would be sent to the victim using the sniff_pkt function provided by the scapy. 		If the hostnames file is not provided then all the traffic would be spoofed with the 		local machines default ip address. If a perticular victim is targetted, then first the 		presence of the victim's source ip is verified and if its present then only its spoofed 	otherwise it is not. Spoofing is done mainly as a callback function in which an 	 		appropriate forged reply is appended to a copy of the DNS response and then it is sent to the 		victim.

-Dnsdetect:
	In this module, all the packets are sniffed and then verified for the presence of a duplicate 		id in a DNS response packet. I have maintained a list which would store all the captured 		packets and when the length of the list is greater than 0, the new incoming packet is compared 		with all the existing packets in the list and if a packet with the same id but different 		response IP is found, the corresponding fields as required are printed as it is the spoofed 		packet. When the length of the list is greater than 30, the initial elements of the list are 		removed. It also functions the same in the offline mode as well. Sniffs the pcap trace file 		and looks for the same difference in the response ip for the same id and prints the results 		accordingly.

Handling the false positives:
	I have looped over the ancount for the current packet and the packet that I have stored already and stored the IP's present in them in two different lists. I am comparing the two lists and if both 		the lists have atleast one ip in common, then I am not treating it as the spoofed packet and if it has no ip in common then I am treating it as the spoofed packet.

Note:
- For the dnsinject.py and densdetect.py, the filter for sniffing on the UDP port 53 has already been applied so do not include the string 'udp port 53' in the bpf filter expression. The expression must include only the targetted victim's ip address only.

- Format of the hostnames file
	13.23.24.12 yandex.com
	12.32.34.54 survi.in

	do not include 'www' in the hostnames file

Running the Program:

DNS inject:

- With all set to defaults
	sudo python3 dnsinject.py
- with all the fields included
	sudo python3 dnsinject.py -i enp0s3 -h hostnames 172.25.23.245

DNS detect:

- With all set to defaults
	sudo python3 dnsdetect.py
- With all the fields included
	sudo python3 dnsdetect.py -i enp0s3 -r mytrace.pcap 172.25.23.245

Results on running the above with yandex.com with mytrace.pcap:

DNS detect:
	WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
	1
	DNS poisioning attempt
	TXID 58616 Request yandex.com
	Answer1 ['10.0.2.15']
	Answer2 ['213.180.204.62']
	1
	DNS poisioning attempt
	TXID 58616 Request yandex.com
	Answer1 ['10.0.2.15']
	Answer2 ['213.180.204.62']
	1
	DNS poisioning attempt
	TXID 62213 Request yandex.com
	Answer1 ['2a02:6b8::11:11']
	Answer2 ['10.0.2.15']

	


References:
- http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
- https://jordan-wright.com/blog/2013/11/15/wireless-attacks-with-python-part-one-the-airpwn-attack/
- https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-2/
- https://programtalk.com/vs2/python/2215/PenTestScripts/DNSInject.py/

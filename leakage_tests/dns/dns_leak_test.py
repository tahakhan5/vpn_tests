
import sys, time, shlex, subprocess, csv
from scapy.all import *
from threading import Thread
from queue import Queue, Empty
from subprocess import call
probes_completed = False

# read input test file which has domains and ip addresses
def read_input_file(file_name):
	domains = []
	ip_addrs =[]

	with open(file_name, 'r') as csvfile:
		domain_reader = csv.reader(csvfile, delimiter=',')
		for row in domain_reader:
			domains.append(row[0])
			ip_addrs.append(row[1].strip("\n"))
	return domains, ip_addrs

# write a a packet to the file
def write_to_file(file_name, raw_packet):
	wrpcap(file_name, raw_packet, append=True)

# continously smiff packets and put them in a queue that is polled
def sniffing_tread(interface, pkt_queue):
	sniff(iface=interface, prn=lambda x : pkt_queue.put(x))

# make DNS requests
def make_requests(domains, ip_addrs):

	global probes_completed

	query_basic = 'dig '
	query_google_dns = 'dig @8.8.8.8 '
	query_any = 'dig ANY '
	query_v6 = 'dig AAAA '
	reverse_query = 'dig -x'
	dns_tcp = 'dig AXFR '

	# execute simple queries
	for domain in domains:
		proc = subprocess.Popen(shlex.split(query_basic+domain), stdout=subprocess.PIPE)
		time.sleep(0.5)

	print('Default DNS queries completed')

	# execute google dns queries
	for domain in domains:
		proc = subprocess.Popen(shlex.split(query_google_dns+domain), stdout=subprocess.PIPE)
		time.sleep(0.5)

	print('Google DNS queries completed')

	# execute dig ANY queries
	for domain in domains:
		proc = subprocess.Popen(shlex.split(query_any+domain), stdout=subprocess.PIPE)
		time.sleep(0.5)

	print('ANY queries completed')
 
	# execute dig v6 queries
	for domain in domains:
		proc = subprocess.Popen(shlex.split(query_v6+domain), stdout=subprocess.PIPE)
		time.sleep(0.5)

	print('DNS V6  only queries completed')

	#  dig reverse query
	for ip_addr in ip_addrs:
		proc = subprocess.Popen(shlex.split(reverse_query+ip_addr), stdout=subprocess.PIPE)
		time.sleep(0.5)

	print('reverse DNS queries completed')

	#  dig axfr transfer for dns over TCP
	for ip_addr in ip_addrs:
		proc = subprocess.Popen(shlex.split(dns_tcp+ip_addr), stdout=subprocess.PIPE)
		time.sleep(0.5)

	print('DNS over TCP completed')

	probes_completed = True


def read_pacp_file(pcap_file):

	leaked_set = set()

	total_packets = 0
	captured_packets = rdpcap(pcap_file)
	
	for packet in captured_packets:
		if packet.haslayer(DNSQR):
			total_packets += 1
			query = packet.getlayer(DNSQR)
			query_str = query.get_field('qname').i2repr(query, query.qname)[1:-2]
			leaked_set.update([query_str])

	print('Found a total of %d domains leaked the DNS responses' % len(leaked_set))
	
def main():

	capture_interface = 'en0'
	output_file = sys.argv[1]+'captured_dns.pcap'

	packet_list = []
	packets = Queue()

	# load the test domains from the file
	domains, ip_addrs = read_input_file('test_sites.csv')

	# start siffing packets on the respective interface
	sniffer = Thread(target=sniffing_tread, args=(capture_interface, packets,))
	sniffer.daemon = Trueargs=(capture_interface, packets,) #)
	sniffer.daemon = True
	sniffer.start()

	# make DNS requests to look for testing
	requester = Thread(target=make_requests, args=(domains, ip_addrs,))
	requester.start()

	while True:
		try:
			pkt = packets.get()
			write_to_file(output_file, pkt)
			packet_list.append(pkt)

			if probes_completed:
				break
		
		except Empty:
			pass
	read_pacp_file(output_file)

if __name__ == '__main__':
	main()
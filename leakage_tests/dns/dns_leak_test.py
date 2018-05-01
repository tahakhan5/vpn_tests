
import csv
import shlex
import subprocess
import time

import scapy.all as sc
from threading import Thread
from queue import Queue, Empty

probes_completed = False

SLEEP_TIME = .05


# read input test file which has domains and ip addresses
def read_input_file(file_name):
    domains = []
    ip_addrs = []

    with open(file_name, 'r') as csvfile:
        domain_reader = csv.reader(csvfile, delimiter=',')
        for row in domain_reader:
            domains.append(row[0])
            ip_addrs.append(row[1].strip("\n"))
    return domains, ip_addrs


# write a a packet to the file
def write_to_file(file_name, raw_packet):
    sc.wrpcap(file_name, raw_packet, append=True)


# continously sniff packets and put them in a queue that is polled
def sniffing_tread(interface, pkt_queue):
    sc.sniff(iface=interface,
             filter="(tcp or udp) and port 53",
             prn=lambda x: pkt_queue.put(x),
             stop_filter=lambda x: probes_completed)


# make DNS requests
def make_requests(domains, ip_addrs):

    global probes_completed

    query_basic = 'dig '
    query_google_dns = 'dig @8.8.8.8 '
    query_any = 'dig ANY '
    query_v6 = 'dig AAAA '
    reverse_query = 'dig -x'
    dns_tcp = 'dig AXFR '

    print('Executing simple queries')

    # execute simple queries
    for domain in domains:
        subprocess.Popen(shlex.split(query_basic + domain),
                         stdout=subprocess.PIPE)
        time.sleep(SLEEP_TIME)

    print('Default DNS queries completed')

    # execute google dns queries
    for domain in domains:
        subprocess.Popen(shlex.split(query_google_dns + domain),
                         stdout=subprocess.PIPE)
        time.sleep(SLEEP_TIME)

    print('Google DNS queries completed')

    # execute dig ANY queries
    for domain in domains:
        subprocess.Popen(shlex.split(query_any + domain),
                         stdout=subprocess.PIPE)
        time.sleep(SLEEP_TIME)

    print('ANY queries completed')

    # execute dig v6 queries
    for domain in domains:
        subprocess.Popen(shlex.split(query_v6 + domain),
                         stdout=subprocess.PIPE)
        time.sleep(SLEEP_TIME)

    print('DNS V6  only queries completed')

    #  dig reverse query
    for ip_addr in ip_addrs:
        subprocess.Popen(shlex.split(reverse_query + ip_addr),
                         stdout=subprocess.PIPE)
        time.sleep(SLEEP_TIME)

    print('reverse DNS queries completed')

    #  dig axfr transfer for dns over TCP
    for ip_addr in ip_addrs:
        subprocess.Popen(shlex.split(dns_tcp + ip_addr),
                         stdout=subprocess.PIPE)
        time.sleep(SLEEP_TIME)

    print('DNS over TCP completed')

    probes_completed = True


def process_packets(packets):

    leaked_set = set()
    total_packets = 0

    while True:
        try:
            packet = packets.get(timeout=1)
        except Empty:
            if probes_completed:
                break
            continue

        if not packet.haslayer(sc.DNSQR):
            continue

        total_packets += 1
        query = packet.getlayer(sc.DNSQR)
        query_str = query.get_field('qname').i2repr(query, query.qname)[1:-2]
        leaked_set.update([query_str])

    print('Found a total of {} domains leaked the DNS responses'.format(
        len(leaked_set)))


def main():

    capture_interface = 'en0'

    packets = Queue()

    # load the test domains from the file
    domains, ip_addrs = read_input_file('test_sites.csv')

    # start siffing packets on the respective interface
    sniffer = Thread(target=sniffing_tread, args=(capture_interface, packets,))
    sniffer.daemon = True
    sniffer.start()

    # make DNS requests to look for testing
    requester = Thread(target=make_requests, args=(domains, ip_addrs,))
    requester.start()

    process_packets(packets)


if __name__ == '__main__':
    main()

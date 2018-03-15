"""
This is essentially Ikram's original test, debugged and cleaned up a bit.

This test works by:
 - connecting to several IPv6 addresses of popular domains
 - collecting traffic on the primary interface while it does so
 - scanning captured traffic for its own IPv6 traffic

If we don't leak IPv6, we shouldn't capture *any* IPv6, assuming the VPN is
using IPv4. We alert only on packets that we emitted just to be safe.

The system will fail quickly if it encounters too many connection errors (e.g
timeouts) on the assumption that IPv6 must not be working at all.

This script returns:
    - 0 if IPv6 didn't leak
    - 2 if it didn't like your arguments
    - 10 if IPv6 DID leak
    - 20 if it bailed early due to connection failures.

Run the script with `sudo`, and use `-h` to see its full options.

It dumps everything it captured to a pcap just for fun.

A separate test covers issues of host isolation and firewalling.

"""

import argparse
import csv
import logging
import os
import socket
import sys

from queue import Queue, Empty
from threading import Thread

import scapy.all as sc

DEFAULT_INTERFACE = 'en0'
DEFAULT_N_CONNECTIONS = 20
DEFAULT_N_ERRORS = 5
DEFAULT_RESOLUTION_FILE = 'v6_resolutions.csv'

LOG_FILE_NAME = 'ipv6.log'
CAP_FILE_NAME = 'captured_ipv6.pcap'

LOG_FORMAT = (
    "%(asctime)s %(levelname)-7s %(name)-8s %(funcName)-20s %(message)s")


logger = logging.getLogger("ipv6")


# read input test file which has domains and ip addresses
def read_input_file(csvfile):
    resolutions = []

    domain_reader = csv.reader(csvfile, delimiter=',')
    for row in domain_reader:

        if len(row) <= 1:
            continue

        ips = [x.strip().lower() for x in row[1:]]
        resolutions.append((row[0], ips))

    return resolutions


# write a a packet to the file
def write_to_file(file_name, raw_packet):
    sc.wrpcap(file_name, raw_packet, append=True)


# continously smiff packets and put them in a queue that is polled
def sniffing_tread(shared):
    def should_exit(pkt):
        return shared['should_exit']

    sc.sniff(iface=shared['interface'], prn=lambda x: shared['pkts'].put(x),
             stop_filter=should_exit)


# make requests to requests
def make_requests(shared, n_connections, n_errors_before_abort):
    resolutions = shared['resolutions']
    n_errors = 0
    for i, (domain, ips) in enumerate(resolutions):
        if n_connections and i >= n_connections:
            break

        # Right now, we're only querying the first resolution per domain
        ip6 = ips[0]

        logger.info("Connecting to %s at %s", domain, ip6)
        try:
            conn_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
            conn_socket.settimeout(2)
            conn_socket.connect((ip6.strip(), 80, 0, 0))
        except Exception as e:
            logger.warning("Connection to %s/%s failed: %s", domain, ip6, e)
            n_errors += 1
            if n_errors >= n_errors_before_abort:
                logger.warning(
                    "Encountered %d errors connecting to IPv6 hosts. "
                    "No IPv6 connectivity?", n_errors)
                sys.exit(1)
            continue

    shared['probes_completed'] = True
    logger.debug("Probes completed.")


def look_for_leaked_dns(packets, resolutions):
    logger.debug("Examining packets for DNS leakage.")

    queried_ips = []
    [queried_ips.extend(y) for (x, y) in resolutions]

    leaked_packets = 0

    # This used to look for DNS packets-- but that's not relevant for us.
    # Our thread directly connects to the IPv6 addresses-- no DNS involved.
    #
    # Instead, we just look to see if it's an IPv6 packet, and if so, if the src
    # or dst might be one of the IPs we queried.
    for packet in packets:
        if packet.haslayer(sc.IPv6):
            src = packet[sc.IPv6].src
            dst = packet[sc.IPv6].dst
            if src in queried_ips or dst in queried_ips:
                leaked_packets += 1

    if leaked_packets:
        logger.error(
            "Detected IPv6 leakage in {} packets".format(leaked_packets))
    else:
        logger.info("No IPv6 leakage detected!")

    return leaked_packets


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="increase verbosity")
    parser.add_argument('-i', '--interface', default=DEFAULT_INTERFACE,
                        help="capture interface")
    parser.add_argument('-n', '--n_connections', default=DEFAULT_N_CONNECTIONS,
                        help=("number of connections to make before exiting."
                              " 0 is 'all'."))
    parser.add_argument('-e', '--error_tolerance', default=DEFAULT_N_ERRORS,
                        help="number of errors to tolerate before exiting.")
    parser.add_argument('-r', '--resolution_file',
                        type=argparse.FileType('r'),
                        default=DEFAULT_RESOLUTION_FILE,
                        help="file to use for resolved ipv6 domains")
    parser.add_argument('output_dir', help="output directory")
    return parser.parse_args()


def setup_logging(verbose, logfile):
    root_logger = logging.getLogger()
    formatter = logging.Formatter(LOG_FORMAT)
    streamhandler = logging.StreamHandler()
    streamhandler.setFormatter(formatter)
    filehandler = logging.FileHandler(logfile)
    filehandler.setFormatter(formatter)
    root_logger.addHandler(streamhandler)
    root_logger.addHandler(filehandler)
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)


def main():
    args = get_args()

    os.makedirs(args.output_dir, exist_ok=True)

    logfile = os.path.join(args.output_dir, LOG_FILE_NAME)
    capfile = os.path.join(args.output_dir, CAP_FILE_NAME)

    setup_logging(args.verbose, logfile)

    # scapy likes to throw warnings.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    if os.geteuid() != 0:
        logging.error("Must run as root when running scapy-based tests.")
        sys.exit(1)

    packet_list = []
    if os.path.exists(capfile):
        os.unlink(capfile)
    packets = Queue()

    # load the test domains from the file
    resolutions = read_input_file(args.resolution_file)

    # start siffing packets on the respective interface
    sniffer_shared = {"should_exit": False, "interface": args.interface,
                      "pkts": packets}
    sniffer = Thread(target=sniffing_tread, args=(sniffer_shared,))
    sniffer.daemon = True
    sniffer.start()

    # make Ipv6 requests to look for testing
    requester_shared = {"resolutions": resolutions, "probes_completed": False}
    requester = Thread(target=make_requests,
                       args=(requester_shared,),
                       kwargs={
                           "n_errors_before_abort": args.error_tolerance,
                           "n_connections": args.n_connections,
                       })
    requester.daemon = True
    requester.start()

    while True:
        try:
            try:
                pkt = packets.get(timeout=1)
            except Empty:
                if requester_shared["probes_completed"]:
                    logger.debug("Detected probes completed.")
                    break
                continue
            except KeyboardInterrupt:
                logger.debug("Exiting from keyboard interrupt.")
                break

            if requester_shared["probes_completed"]:
                sniffer_shared['should_exit'] = True

            write_to_file(capfile, pkt)
            packet_list.append(pkt)

        except Empty:
            pass
    sniffer_shared['should_exit'] = True

    leaked_packets = look_for_leaked_dns(packet_list, resolutions)
    return 10 if leaked_packets > 0 else 0

if __name__ == '__main__':
    sys.exit(main())

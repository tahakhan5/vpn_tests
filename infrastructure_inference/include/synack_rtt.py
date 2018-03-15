"""TODO: Change me!"""

from __future__ import print_function

import logging
import os
import random
import subprocess
import signal
import sys
import tempfile
import threading
import time

from collections import defaultdict
from pprint import pprint

import scapy.all as sc
import requests

INTERTARGET_TIME_SECONDS = .02

_TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}

logger = logging.getLogger("synack_rtt")


def _start_capture(pkt_file):
    # Thanks to pktap magic, we can filter to just our app's traffic
    pid = os.getpid()
    p = subprocess.Popen(["tcpdump", "-w", pkt_file, "-Q", "pid=" + str(pid)],
                         stderr=subprocess.DEVNULL)
    time.sleep(1)
    return p


def _stop_capture(p):
    time.sleep(1)

    if p.poll() is not None:
        logger.warning("Capture already exited...")
        return

    SIGNALS = [signal.SIGINT, signal.SIGTERM, signal.SIGKILL]
    for sgnl in SIGNALS:
        p.send_signal(signal.SIGINT)
        rt = p.wait(timeout=2)
        if rt is not None:
            break

    if rt is None:
        logger.error("Couldn't kill tcpdump!")



def _measure_rtts(pkt_file, targets):
    pending = {}

    rtts = defaultdict(list)

    packets = sc.rdpcap(pkt_file)
    for pkt in packets:
        ip = pkt[sc.IP]
        tcp = pkt[sc.TCP]
        flags = tcp.flags

        # SYN
        if flags & _TCP_FLAGS["SYN"] and not (flags & _TCP_FLAGS["ACK"]):
            if ip.dst not in targets:
                continue

            tpl = (ip.src, ip.dst, tcp.sport, tcp.dport, tcp.seq)
            pending[tpl] = (pkt.time, pkt)

        # SYN-ACK
        elif flags & _TCP_FLAGS["SYN"] | _TCP_FLAGS["ACK"]:
            if ip.src not in targets:
                continue

            tpl = (ip.dst, ip.src, tcp.dport, tcp.sport, tcp.ack - 1)
            if tpl in pending:
                rtt = (pkt.time - pending[tpl][0]) * 1000
                logger.info("> RTT from {} to {} took {} ms".format(
                    ip.dst, ip.src, rtt
                ))
                rtts[ip.src].append(rtt)
                del pending[tpl]

    return dict(rtts)


def _send_syn(target):
    # This *used* to just send a single syn followed by a rst.
    # Scapy occasionally segfaults for me under python3 with packet generation
    # so now we just do this.
    #
    # We timeout immediately because frankly we don't care about the request.
    try:
        requests.get("https://" + target, stream=True, timeout=.1)
    except:
        pass


def _multi_syn(targets, n):
    for i in range(n):
        for target in targets:
            _send_syn(target)
            time.sleep(INTERTARGET_TIME_SECONDS)


def get_rtts(targets, n=10):
    # Scapy has issues with closing file handles sometimes.
    # It complains about it a LOT. That leads us to having a LOT of warnings.
    # This line suppresses them.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Using the requests method, you're gonna end up with a LOT of certificate
    # mismatches..
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

    targets = set(targets)

    pkt_file = tempfile.mktemp()
    logger.info("Starting capture")
    capture_process = _start_capture(pkt_file)

    logger.info("Starting SYN/SYN-ACK measurements")
    _multi_syn(targets, n)

    logger.info("Stopping capture")
    _stop_capture(capture_process)

    logger.info("Measuring RTTs")
    rtts = _measure_rtts(pkt_file, targets)

    return rtts


def main():
    logging.basicConfig(
        format='%(asctime)-15s %(levelname)s %(module)s %(message)s',
        level=logging.INFO)

    targets = ["132.239.180.101"]
    #targets = ["46.22.79.34"]
    pprint(get_rtts(targets))


if __name__ == "__main__":
    sys.exit(main())

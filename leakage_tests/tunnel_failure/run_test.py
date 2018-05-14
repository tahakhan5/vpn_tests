#!/usr/bin/env python3
"""Leakage test when VPN fails."""

import argparse
import atexit
import logging
import os
import re
import socket
import subprocess
import sys
import time
import http.client


DEFAULT_CONFIG = '/etc/pf.conf'

DEFAULT_INPUT_FILE = 'hosts.txt'
INTERFACE_NAME = 'en0'

PF_TOKEN = None

SLEEP_TIME = 60
N_PERIODS = 3

LOG_FORMAT = '%(asctime)-15s %(levelname)s %(message)s'


logger = logging.getLogger("tun_fail")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--hosts',
                        default=os.path.join(os.getcwd(), DEFAULT_INPUT_FILE),
                        type=argparse.FileType('r'),
                        #type=ForgivingFileType('r'),
                        help=("file of hosts to test, defaulting to ./" +
                              DEFAULT_INPUT_FILE))
    parser.add_argument('--interface', nargs=1,
                        default=INTERFACE_NAME,
                        help=("outbound interface, defaulting to " +
                              INTERFACE_NAME))
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="increase verbosity")
    parser.add_argument('-o', '--output', help="output log file")
    return parser.parse_args()


def run(cmd, stdin=None, timeout=2):
    """Run the cmd (a list), passing in the string stdin."""
    PIPE = subprocess.PIPE
    # This is so much nicer if we could rely on python3.5 or better.
    process = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return process.communicate(stdin, timeout=timeout)


def add_anchor_and_activate():
    """Activates pf and adds our anchor for our rules."""
    # echo 'anchor vpn_test' | cat /etc/pf.conf - | sudo pfctl -f - -E
    global PF_TOKEN

    with open(DEFAULT_CONFIG, 'r', encoding='utf-8') as f:
        old_config = f.read()
    new_config = old_config + "anchor vpn_test\n"

    _, err = run(['pfctl', '-f', '-', '-E'], stdin=new_config.encode('utf-8'))

    last_line = err.decode('utf-8').rstrip().split("\n")[-1]
    match = re.match("Token : (\d+)", last_line)
    if not match:
        raise Exception("No token found in output:", last_line)

    PF_TOKEN = match.group(1)


def get_pf_rules(target_ips, iface):
    """Generate a pf configuration to block non-test traffic."""
    output = "block all\n"
    # We 'should' be doing this with a table, but Mac's pf auto-converts
    # it so it doesn't matter.
    for ip in target_ips:
        output += (
            "\npass out on {iface} proto tcp from any to {ip} port 80\n"
            "pass in on {iface} proto tcp from {ip} port 80 to any\n").format(
                iface=iface, ip=ip)
    return output


def add_blocking_rules(target_ips, iface):
    """Adds pf rules to block all traffic."""
    block_config = get_pf_rules(target_ips, iface)
    run(['pfctl', '-a', 'vpn_test', '-f', '-'],
        stdin=block_config.encode('utf-8'))


@atexit.register
def deconfigure_pf():
    """Return pf to original configuration.

    Decorator calls us automatically at exit.

    Flushes vpn_test anchor, and kills pf if we're the only one using it.
    """

    if not PF_TOKEN:
        return
    logger.debug("Flushing firewall.")
    run(['pfctl', '-a', 'vpn_test', '-F', 'all', '-X', PF_TOKEN])


def try_connect(target_ips, timeout=2):
    """Try to connect to each IP. Return the HTTP status from each."""
    results = []
    for ip in target_ips:
        try:
            c = http.client.HTTPConnection(ip, timeout=timeout)
            c.request("GET", "")
            r = c.getresponse()
            result = r.status
        except socket.timeout:
            result = None
            logger.debug("Connection to {} failed: timeout".format(ip))
        except Exception:
            result = None
            logger.exception(
                "Connection to {} failed with unexpectedly".format(ip))
        results.append((ip, result))
    return results


def get_ips_from_hostnames(hosts):
    return [socket.gethostbyname(x) for x in hosts]


def get_connect_count(target_ips, timeout=2):
    """Attempt connections to target_ips and return how many succeeded."""
    # If python3 still had reduce, this would have been a 1-liner...
    results = try_connect(target_ips, timeout=timeout)
    count = 0
    for h, r in results:
        if r is not None:
            count += 1
    return count


def setup_logging(verbose, logfile=None):
    root_logger = logging.getLogger()
    formatter = logging.Formatter(LOG_FORMAT)
    streamhandler = logging.StreamHandler()
    streamhandler.setFormatter(formatter)
    root_logger.addHandler(streamhandler)

    if logfile:
        filehandler = logging.FileHandler(logfile)
        filehandler.setFormatter(formatter)
        root_logger.addHandler(filehandler)

    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)


def main():
    args = get_args()
    setup_logging(args.verbose, args.output)

    if os.geteuid() != 0:
        logger.error("Must run as root.")
        sys.exit(1)

    hosts = [x.rstrip() for x in args.hosts.readlines()
             if not x.startswith("#")]
    target_ips = get_ips_from_hostnames(hosts)

    logger.info("Mapping hosts to IPs")
    for x, y in zip(hosts, target_ips):
        logger.debug("Mapped host {} to {}".format(x, y))

    prev = time.time()

    # - Establish baseline connectivity
    logger.info("Establishing baseline")
    connect_count = get_connect_count(target_ips)
    passed = connect_count > len(target_ips) / 2
    logger.info("Initial connection count: {} of {} ({})".format(
        connect_count, len(target_ips), "PASS" if passed else "FAIL"))
    if not passed:
        sys.exit(3)

    # - Configure pf with the extra anchor and -E
    # - Load the anchor rules
    logger.info("Blocking connections.")
    add_anchor_and_activate()
    add_blocking_rules(target_ips, args.interface)

    for i in range(N_PERIODS):
        sleep_time = SLEEP_TIME - time.time() + prev
        logger.info("Sleeping for {:.2f}s.".format(sleep_time))
        time.sleep(sleep_time)
        prev = time.time()

        logger.info("Checking connectivity...")
        connect_count = get_connect_count(target_ips)
        passed = connect_count == 0
        logger.info("Check #{}/{} count: {} of {} ({})".format(
            i + 1, N_PERIODS, connect_count, len(target_ips),
            "PASS" if passed else "FAIL"))
        if not passed:
            sys.exit(4 + i)

    logger.info("All tests passed!")

    # - AT EXIT, flush new rules and reconfigure pf w/o anchor and -X token

if __name__ == "__main__":
    sys.exit(main())

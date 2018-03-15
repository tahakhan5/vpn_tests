"""Utility functions for running basic infrastructure tests."""

import json
import logging
import re
import ssl
import subprocess
import sys
import time

import requests

import tracerouteparser

COMMENT_PATTERN = re.compile("#.*")


def get_file_contents(filename):
    """Just a wrapper around read(), but stripping comments and whitespace."""
    with open(filename) as f:
        lines = [COMMENT_PATTERN.sub("", x).strip() for x in f.readlines()]
    return [x for x in lines if x]


def google_dns_lookup(hostname, session=None):
    """Try to do a normal DNS query for the given hostname.

    Returns IP as string or None on failure.

    This should work for a standard A query where there's a result, which is
    good enough for our purposes.

    """
    if not session:
        session = requests.Session()
    try:
        resp = session.get(
            "https://dns.google.com/resolve",
            params={"name": hostname},
            timeout=3.0)
    except ssl.SSLError as e:
        logging.warning(
            "Google DNS lookup failed with SSL error!: {}".format(e))
        return None
    except requests.exceptions.Timeout:
        logging.warning("Google DNS lookup timed out!")
        return None

    CODE_TO_NAME = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
        6: "YXDOMAIN",
        7: "YXRRSET",
        8: "NXRRSET",
        9: "NOTAUTH",
        10: "NOTZONE",
    }

    result = resp.json()
    status = result["Status"]
    if status != 0:
        logging.info(
            "Google DNS lookup failed with DNS response: {}".format(
                CODE_TO_NAME.get(status, "UNKNOWN ({})".format(status))))
        return None

    for answer in result["Answer"]:
        if answer["type"] == 1:
            return answer["data"]

    logging.warning("Couldn't find A-record in lookup response to: {}".format(
        CODE_TO_NAME.get(status, "UNKNOWN ({})".format(status))))
    return None


PING_PATTERN = re.compile("""PING [0-9.]+ \([0-9.]+\): [0-9]+ data bytes

--- [0-9.]+ ping statistics ---
(\d+) packets transmitted, (\d+) packets received, [0-9.]+% packet loss
round-trip min/avg/max/stddev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms""")


def fetch_web_contents(address):
    """Fetches web contents and returns it or an error."""
    try:
        response = requests.get(address, timeout=3)
        if response.ok:
            return (response.text, None)
        else:
            return (None,
                    "Failed: {}/{}\n".format(
                        response.status_code, response.reason))
    except requests.exceptions.ConnectionError as e:
        return (None, repr(e))
    except requests.exceptions.Timeout as e:
        return (None, repr(e))


def process_ping_output(stdout):
    if stdout is None:
        return None

    m = PING_PATTERN.match(stdout.decode("utf-8"))
    if not m:
        return None

    return dict(zip(["NSent", "NRec", "MinRTT", "AvgRTT", "MaxRTT", "Std"],
                    [float(x) for x in m.groups()]))


def get_ping_stats(host):
    stdout, stderr = run(["ping", "-t3", "-c20", "-nq", "-i0.1", host])
    #timeout=5)
    if stderr:
        return None
    return process_ping_output(stdout)


def ping_all(hosts):
    return [(x, get_ping_stats(x)) for x in hosts]


def get_ips(hosts):
    with requests.Session() as session:
        return [(x, google_dns_lookup(x, session=session)) for x in hosts]


def run(cmd, stdin=None, timeout=None):
    """Run the cmd (a list), passing in the string stdin."""
    # TODO - assume we're python3.4 or above...

    PIPE = subprocess.PIPE
    # This is so much nicer if we could rely on python3.5 or better.
    # ...or even python3.4 in a scapy-compatible world :-(
    kwargs = {}
    if sys.version_info.major == 3 and sys.version_info.minor >= 3:
        kwargs["timeout"] = timeout
    elif timeout is not None:
        logging.warning("timeout not supported in python versions <3.3")

    process = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return process.communicate(stdin, **kwargs)


def nrun(cmds, timeout=None, delay=None):
    """Run each of the cmds, passing in the string stdin.

    Assume we are running python3.4 or above on this one.
    """
    PIPE = subprocess.PIPE

    processes = []
    for cmd in cmds:
        process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                   stdout=PIPE, stderr=PIPE)
        processes.append(process)

        if delay:
            time.sleep(delay)

    for p in processes:
        try:
            p.wait(timeout=timeout)
        except sp.TimeoutExpired:
            p.kill()

    return [(p.stdout.read(), p.stderr.read()) for p in processes]


class TracerouteParserJSONEncoder(json.JSONEncoder):
    """Just so we can dump to json nicely.

    Not currently used, but if you wanted to, you could so something like this:
        import tracerouteparser
        stdout, stderr = utils.run(["traceroute", "8.8.8.8"])
        traceroute = stderr + "\n" + stdout
        tp = tracerouteparser.TracerouteParser()
        tp.parse_data(traceroute)
        print(json.dumps(tp, cls=utils.TracerouteParserJSONEncoder))
    """

    def default(self, o):
        if (
                isinstance(o, tracerouteparser.TracerouteParser) or
                isinstance(o, tracerouteparser.Probe) or
                isinstance(o, tracerouteparser.Hop)):
            return o.__dict__

        return json.JSONEncoder.default(self, o)

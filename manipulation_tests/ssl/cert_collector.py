import base64
import json
import logging
import os.path
import socket
import ssl
import sys
import traceback

import requests

from collections import OrderedDict
from urllib.parse import urlparse

# Dump the SSL ssl certificates of the websites in

from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed


# Some embarrasing monkey-patching to get our peer cert up into the response
# objects of redirected requests.
# From https://stackoverflow.com/questions/16903528/
HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__
def new_HTTPResponse__init__(self, *args, **kwargs):  # noqa
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        self.peercert = self._connection.sock.getpeercert()
    except AttributeError as e:
        pass
HTTPResponse.__init__ = new_HTTPResponse__init__  # noqa

HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response
def new_HTTPAdapter_build_response(self, request, resp):  # noqa
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peercert = resp.peercert
    except AttributeError:
        pass
    return response
HTTPAdapter.build_response = new_HTTPAdapter_build_response  # noqa


# Imperfect, but closer-to-real Chrome-like headers for requests
STATIC_HEADERS = OrderedDict([
    ("Connection", "keep-alive"),
    ("Upgrade-Insecure-Requests", "1"),
    ("User-Agent",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36"
     "(KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36"),
    ("Accept",
     "text/html,application/xhtml+xml,application/xml;"
     "q=0.9,image/webp,image/apng,*/*;q=0.8"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Accept-Language", "en-US,en;q=0.9"),
])


LOG_FORMAT = (
    "%(asctime)s %(levelname)-7s %(name)-8s %(funcName)-15s %(message)s")


logger = logging.getLogger("ssl")


Mode = namedtuple("Mode", ['fetch_cert', 'fetch_http',
                           'save_body', 'save_json'])


def parse_mode(stm):
    fetch_cert = False
    fetch_http = False
    save_body = False
    save_json = False
    for c in stm:
        if c == 'a':
            fetch_cert = True
            fetch_http = True
        elif c == 's':
            save_body = True
            fetch_http = True
        elif c == 'j':
            save_json = True
            fetch_http = True
        elif c == 'c':
            fetch_cert = True
        elif c == 'h':
            fetch_http = True
        else:
            raise KeyError("Unknown specifier " + c)

    return Mode(fetch_cert, fetch_http, save_body, save_json)


def flatten_cookiejar(jar):
    cookies = []
    for cookie in jar:
        cookies.append(cookie.__dict__)
    return cookies


# Janky serialization of non-serializable response objects
def facilitate_serialize(x, history=False):
    dump_fields = [
        ("status_code", lambda x: x),
        ("links", lambda x: x),
        ("headers", lambda x: list(x.items())),  # headers have order
        ("peercert", lambda x: x),
        ("reason", lambda x: x),
        ("url", lambda x: x),
        ("encoding", lambda x: x),
        ("cookies", flatten_cookiejar),
        ("elapsed", lambda x: x.total_seconds()),
    ]

    d = dict()
    for k, c in dump_fields:
        d[k] = c(getattr(x, k, None))
    if history:
        d["history"] = [facilitate_serialize(y) for y in x.history]
    return d


def get_asn1(hostname, timeout=5):
    if "/" in hostname:
        return None

    ctx = ssl.SSLContext()
    ctx.set_ciphers("ALL")  # Come one, come all.
    sock = socket.socket()
    sock.settimeout(timeout)
    s = ctx.wrap_socket(sock, server_hostname=hostname)
    s.connect((hostname, 443))

    # binary because otherwise returns empty dict when verification fails
    asn1 = s.getpeercert(True)

    return base64.encodebytes(asn1).decode('utf-8')


def load_asn1(inp):
    import OpenSSL
    res = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, inp)
    return res


def get_host_data(host, result, mode):
    """Look for SSL-based attacks for a host."""

    # First, try to do an HTTP request to see if we're downgraded.
    # We use static headers that look like modern chrome.
    try:
        if mode.fetch_http:
            r = requests.get("http://" + host,
                             headers=STATIC_HEADERS, timeout=5)
            result['response'] = facilitate_serialize(r, True)
            if mode.save_body:
                result['body'] = r.text
            if mode.save_json:
                result['body'] = r.json()
    except requests.exceptions.SSLError as e:
        result['request_error'] = "SSLError"
        #... yes really
        result['request_error_details'] = e.args[0].reason.args[0].args[0]
    except requests.exceptions.ReadTimeout as e:
        result['request_error'] = "ReadTimeout"
    except requests.exceptions.ConnectionError as e:
        result['request_error'] = "ConnectionError"
        try:
            result['request_error_details'] = str(e.args[0].reason.args[0])
        except AttributeError:
            result['request_error_details'] = str(e.args[0])
    except requests.exceptions.ConnectTimeout as e:
        result['request_error'] = "ConnectionTimeout"
        result['request_error_details'] = 5
    except TimeoutError as e:
        result['request_error'] = "TimeoutError"
    except AttributeError as e:
        result['request_error'] = "UNKNOWN_ERROR"
        result['request_error_details'] = str(e)

    # Also record the certificate of the host.
    try:
        if mode.fetch_cert:
            result['cert'] = get_asn1(host)
    except socket.timeout as e:
        result['cert_error'] = "SOCK_TIMEOUT"
    except TimeoutError as e:
        result['cert_error'] = "TIMEOUT"
    except ConnectionRefusedError as e:
        result['cert_error'] = "CONN_REFUSED"
    except BrokenPipeError as e:
        result['cert_error'] = "BROKEN_PIPE"
    except ConnectionResetError as e:
        result['cert_error'] = "CONN_RESET"
    except ssl.CertificateError as e:
        result['cert_error'] = "CERT_ERROR"
        result['cert_error_details'] = str(e)
    except ssl.SSLError as e:
        result['cert_error'] = "SSL_ERROR"
        result['cert_error_details'] = str(e)
    except socket.gaierror as e:
        result['cert_error'] = "GAI_ERROR"

    if 'cert_error' in result:
        logger.warning(
            "%s Collecting Cert for: %s", result['cert_error'], host)

    # If we successfully loaded a page after redirects, and the ultimate host
    # wasn't just `host`:443, then let's grab that certificate too, just for
    # completeness.
    parts = urlparse(
        result['response']['url']) if 'response' in result else None
    if parts and parts.scheme == 'https':
        if parts.netloc != host:
            try:
                result['final_dest_cert'] = get_asn1(parts.netloc)
            except Exception as e:
                result['final_dest_cert_error'] = str(e)


def try_fetch(host, mode):
    data = {"host": host}
    try:
        get_host_data(host, data, mode)
    except Exception as e:
        logger.exception("ERROR Collecting Cert for: %s", host)
        data["error"] = "UNKNOWN_ERROR:" + str(e)
        traceback.print_exc()

    sys.stdout.flush()
    return host, json.dumps(data)


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
    setup_logging(False)

    results_dir = sys.argv[1]
    out_file = open(os.path.join(results_dir, "ssl_certs.json"), 'w')
    futures = []
    with open('hosts.txt') as f:
        with ThreadPoolExecutor(max_workers=10) as e:
            n_hosts = 0
            for line in f:
                n_hosts += 1
                mode, host = line.strip("\n").split(",", maxsplit=1)
                mode = parse_mode(mode)
                futures.append(e.submit(try_fetch, host, mode))

            for i, future in enumerate(as_completed(futures)):
                host, data = future.result()
                if not data:
                    continue
                logger.info("SUCCESS Collecting data for: %s [%d/%d]",
                            host, i + 1, n_hosts)
                out_file.write(data)
                out_file.write("\n")


if __name__ == "__main__":
    main()

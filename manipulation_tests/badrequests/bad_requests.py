"""Send bogus requests to an echo server.

If we get responses back from the echo server that are inconsistent with what
we sent, that's indicative of a middlebox.

This idea is from OONI, but the hacky implementation is my own.

The hard-coded echo server responds with valid HTTP replies where the body is a
base64-encoded version of the raw request (headers and all).

"""

import argparse
import base64
import difflib
import json
import os
import random
import re
import socket
import string
import sys
import time
import traceback

from io import StringIO, BytesIO


SLEEP_TIME = .1


HEADERS = {
    "chrome": [
        ("Host", "pong.projekts.xyz"),
        ("Connection", "keep-alive"),
        ("Pragma", "no-cache"),
        ("Cache-Control", "no-cache"),
        ("Upgrade-Insecure-Requests", "1"),
        ("User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4)"
            " AppleWebKit/537.36 (KHTML, like Gecko)"
            " Chrome/66.0.3359.139 Safari/537.36"),
        ("Accept",
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/webp,image/apng,*/*;q=0.8"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Accept-Language", "en-US,en;q=0.9"),
    ],
    "safari": [
        ("Host", "pong.projekts.xyz"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Accept",
         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("User-Agent",
         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4)"
         " AppleWebKit/605.1.15 (KHTML, like Gecko)"
         " Version/11.1 Safari/605.1.15"),
        ("Accept-Language", "en-us"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Connection", "keep-alive"),
    ],
    "firefox": [
        ("Host", "pong.projekts.xyz"),
        ("User-Agent",
         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0)"
         " Gecko/20100101 Firefox/59.0"),
        ("Accept",
         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("Accept-Language", "en-US,en;q=0.5"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1"),
    ],
}


ECHO_HOST = ("pong.projekts.xyz", 80)

DOUBLE_LINE = re.compile(b"\n\r?\n\r?")


VERBS = [
    "GET", "POST", "PUT", "DELETE", "TRACE",
    "get", "Get", "geT", "GeT",
    "FAKEVERB", "DASHED-VERB", "USCORE_VERB",
    "".join(["LONGVERB" for x in range(1000)]),
    "CONNECT"
]

PATHS = [
    "/", "/pong", "/pong?apple=sauce", "/pong?apple=sauce&pumpkin=patch",
    "/".join(["a" for x in range(1000)]),
]

PROTOS = [
    "HTTP/1.0", "HTTP/1.1", "HTTP/1", "HTTP/2.0", "HTTP/2",
    "http/1.0", "http/1.1", "http/1", "http/2.0", "http/2",
    "FOOBAR/1.0", "Foo_Bar/1.1", "foo-bar/1",
    "HTTP/1.00", "HTTP/10", "HTTP/1.0.0.0", "HTTP/9.9",
    "HTTP/1.0  ", " HTTP/1.0",
    "HTTP", "HTTP\\1.0",
    "".join("HT" for x in range(1000)) + "/1.0",
    "HTTP/" + "".join("1" for x in range(1000)),
]


def rand_case(st):
    return "".join(
        x.upper() if random.randint(0, 1) else x.lower() for x in st)


def rand_host():
    return (
        "".join(random.choice(string.ascii_letters + string.digits)
                for _ in range(12)) +
        "." +
        "".join(random.choice(string.ascii_letters + string.digits)
                for _ in range(random.randint(2, 5)))
    )


CHROME_HEADERS = HEADERS['chrome']
HEADER_SETS = [
    CHROME_HEADERS[:1] +
    [("LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG",
      "header value")] + CHROME_HEADERS[1:],
    CHROME_HEADERS[:1] +
    [("LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG",
      "".join("VALUE" for _ in range(1000)))] + CHROME_HEADERS[1:],
    CHROME_HEADERS[:5] + CHROME_HEADERS[4:],
    CHROME_HEADERS + [("User-Agent",
                       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4)"
                       " AppleWebKit/537.36 (KHTML, like Gecko)"
                       " Chrome/66.0.3356.129 Safari/547.36")],
    (CHROME_HEADERS[:5] + [("User-Agent",
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4)"
                            " AppleWebKit/537.36 (KHTML, like Gecko)"
                            " Chrome/66.0.3356.129 Safari/547.36")] +
     CHROME_HEADERS[5:]),
    random.sample(CHROME_HEADERS, k=len(CHROME_HEADERS)),
    random.sample(CHROME_HEADERS, k=len(CHROME_HEADERS)),
    random.sample(CHROME_HEADERS, k=len(CHROME_HEADERS)),
    random.sample(CHROME_HEADERS, k=len(CHROME_HEADERS)),
    CHROME_HEADERS[:3] + [CHROME_HEADERS[3]] * 100 + CHROME_HEADERS[4:],
    HEADERS['firefox'],
    HEADERS['safari'],
    [(rand_case(x), rand_case(y)) for (x, y) in CHROME_HEADERS],
]

# Just some random invalid hosts.
RAND_HOSTS = [
    [("Host", rand_host())] + CHROME_HEADERS[1:],
    [("Host", rand_host())] + CHROME_HEADERS[1:],
    [("Host", rand_host())] + CHROME_HEADERS[1:],
    [("Host", rand_host())] + CHROME_HEADERS[1:],
    [("Host", rand_host())] + CHROME_HEADERS[1:],
    [("Host", rand_host())] + CHROME_HEADERS[1:],
]


def read_all(sock):
    data = BytesIO()
    while True:
        try:
            new_data = sock.recv(65535)
        except OSError as e:
            print(e)
            break

        if not new_data:
            break

        data.write(new_data)
    return data.getvalue()


def try_extract_body(response):
    match = DOUBLE_LINE.split(response, 1)
    if not match or len(match) == 1:
        return None

    body = match[1]
    decoded = base64.decodebytes(body)
    return decoded.decode('utf8')


def send_request(verb, path, proto, data=None, headers=CHROME_HEADERS):
    result = {
        "verb": verb,
        "path": path,
        "proto": proto,
        "body": data,
        "headers": headers,
    }
    response = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.settimeout(2)
        #sys.stderr.write("Addr: {}\n".format(addr))

        try:
            s.connect(ECHO_HOST)
        except socket.gaierror:
            result['result'] = 'connect_error'
            result['error'] = "gai_error"
            return result
        except PermissionError:
            result['result'] = 'connect_error'
            result['error'] = "permission_error"
            return result
        except ConnectionRefusedError:  # noqa
            result['result'] = 'connect_error'
            result['error'] = "connection_refused"
            return result
        except socket.timeout:
            result['result'] = 'connect_error'
            result['error'] = "timeout"
            return result

        sio = StringIO()
        sio.write("{} {} {}\n".format(verb, path, proto))

        for header, body in headers:
            sio.write("{}: {}\n".format(header, body))
        sio.write("\n")

        request = sio.getvalue()
        result['request'] = request

        try:
            s.send(request.encode('utf8'))

            if data:
                s.send(data)

            data = read_all(s)
            response = try_extract_body(data)
            if not response:
                return (False, "no_extracted_body")

            diff_response = [
                x + "\n"
                for x in response.replace("\r", "\\r").split("\n")]

            diff_request = [
                x + "\n"
                for x in request.replace("\r", "\\r").split("\n")]

            diff = list(difflib.context_diff(diff_request, diff_response,
                                             'request', 'response',
                                             lineterm='\n'))
        except Exception as e:
            result['result'] = 'request_error'
            result['error'] = str(type(e)) + ":" + str(e)

        result['response'] = response

        if diff:
            result['result'] = 'diff'
            result['diff'] = diff
        else:
            result['result'] = 'ok'

        s.close()

    except Exception as e:
        traceback.print_exc()
        result['result'] = 'unexpected_error'
        result['error'] = str(type(e)) + ":" + str(e)

    return result


def send_and_print_differences(
        errors, verb, path, proto, body=None, headers=CHROME_HEADERS):

    result = send_request(verb, path, proto, body, headers=headers)

    # This should never happen
    if 'result' not in result:
        print("No result present in", result)
        return -1

    # Print that there was an error if applicable.
    if result['result'] in {"unexpected_error", "request_error",
                            "connect_error"}:
        print("Error in: ", verb[:50], path[:50], proto[:50])
        r = 1

    # Print the diff if there is one.
    if result['result'] == 'diff':
        r = 1
        for line in result['diff']:
            sys.stdout.write(line)

    # Only save away the errors
    if result['result'] != 'ok':
        errors.append(result)
        return 1

    return 0


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('outdir', help="Output directory")
    return parser.parse_args()


def main():
    args = get_args()

    errors = []

    cnt = 0
    for i, (k, headers) in enumerate(HEADERS.items()):
        print("===== headers for", k)
        cnt += send_and_print_differences(
            errors, "GET", "/", "HTTP/1.0", headers=headers)
        time.sleep(SLEEP_TIME)
        cnt += send_and_print_differences(
            errors, "GET", "/", "HTTP/1.1", headers=headers)
        time.sleep(SLEEP_TIME)

    for verb in VERBS:
        print("===== verb", verb[:50])
        cnt += send_and_print_differences(errors, verb, "/", "HTTP/1.0")
        time.sleep(SLEEP_TIME)
        cnt += send_and_print_differences(errors, verb, "/", "HTTP/1.1")
        time.sleep(SLEEP_TIME)

    for path in PATHS:
        print("===== path", path[:50])
        cnt += send_and_print_differences(errors, "GET", path, "HTTP/1.0")
        time.sleep(SLEEP_TIME)
        cnt += send_and_print_differences(errors, "GET", path, "HTTP/1.1")
        time.sleep(SLEEP_TIME)

    for proto in PROTOS:
        print("===== proto", proto[:50])
        cnt += send_and_print_differences(errors, "GET", "/", proto)
        time.sleep(SLEEP_TIME)

    for i, header in enumerate(HEADER_SETS):
        print("===== header set", i)
        cnt += send_and_print_differences(
            errors, "GET", "/", "HTTP/1.0", headers=header)
        time.sleep(SLEEP_TIME)
        cnt += send_and_print_differences(
            errors, "GET", "/", "HTTP/1.1", headers=header)
        time.sleep(SLEEP_TIME)

    for headers in RAND_HOSTS:
        print("===== host", headers[0][1])
        cnt += send_and_print_differences(
            errors, "GET", "/", "HTTP/1.0", headers=header)
        time.sleep(SLEEP_TIME)
        cnt += send_and_print_differences(
            errors, "GET", "/", "HTTP/1.1", headers=header)
        time.sleep(SLEEP_TIME)

    with open(os.path.join(args.outdir, "bad_requests.json"), 'w') as f:
        json.dump(errors, f)

    return cnt


if __name__ == "__main__":
    sys.exit(main())

import json
import os.path
import socket
import ssl
import sys
import traceback

# Dump the SSL ssl certificates of the websites in

from concurrent.futures import ThreadPoolExecutor, as_completed


def get_x509(hostname):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
    s.connect((hostname, 443))
    x509 = s.getpeercert()
    data = {hostname: x509}
    return data


def try_fetch(host):
    data = None
    try:
        data = get_x509(host)
    except TimeoutError as e:
        print("TIMEOUT Collecting Cert for:", host)
    except ConnectionRefusedError as e:
        print("CONN_REFUSED Collecting Cert for:", host)
    except BrokenPipeError as e:
        print("BROKEN_PIPE Collecting Cert for:", host)
    except ConnectionResetError as e:
        print("CONN_RESET Collecting Cert for:", host)
    except ssl.CertificateError as e:
        print("CERT_ERROR Collecting Cert for:", host, e)
    except ssl.SSLError as e:
        print("SSL_ERROR Collecting Cert for:", host, e)
    except Exception as e:
        print("ERROR Collecting Cert for:", host)
        traceback.print_exc()
    sys.stdout.flush()
    return host, data


def main():

    results_dir = sys.argv[1]
    out_file = open(os.path.join(results_dir, "ssl_certs.json"), 'w')
    futures = []
    with open('hosts.txt') as f:
        with ThreadPoolExecutor(max_workers=10) as e:
            n_hosts = 0
            for line in f:
                n_hosts += 1
                host = line.strip("\n")
                futures.append(e.submit(try_fetch, host))

            for i, future in enumerate(as_completed(futures)):
                host, data = future.result()
                if not data:
                    continue
                print("SUCCESS Collecting Cert for:", host,
                      " [{}/{}]".format(i + 1, n_hosts))
                json.dump(data, out_file)
                out_file.write("\n")


if __name__ == "__main__":
    main()

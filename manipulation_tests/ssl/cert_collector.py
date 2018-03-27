import sys, ssl, socket, json

# Dump the SSL ssl certificates of the websites in

def get_x509(hostname):
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
    s.connect((hostname, 443))
    x509 = s.getpeercert()
    data = {hostname: x509}
    return data

def main():

    results_dir = sys.argv[1]
    out_file = open(results_dir+"ssl_certs.json", 'w')
    with open('hosts.txt') as f:
        for line in f:
            try:
                host = line.strip("\n")
                data = get_x509(host)
                json.dump(data, out_file)
                out_file.write("\n")
                print("SUCCESS Collecting Cert for: "+host)
            except:
                print("ERROR Collecting Cert for: "+host)
                continue

if __name__ == "__main__":
    main()


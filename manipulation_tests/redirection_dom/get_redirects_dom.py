import argparse
import json
import os
import os.path
import sys
import time
import traceback

from concurrent.futures import ThreadPoolExecutor, as_completed

from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By

# TODO - when sites timeout (from set_page_load_timeout) they throw an
#        exception that causes a return to main. That means that it doesn't
#        write any partial results that may be available.

DEFAULT_HOSTS_FILE = "hosts.txt"

# How long to wait for a page to finish loading
DEFAULT_TIMEOUT_S = 30

# Number of threads to run simultaneously?
# This makes timeouts go through the roof, though...
NUM_WORKERS = 3

# These are just used for status updating. I don't protect them with locks
# because they're just for human feedback.
n_processed = 0
n_queued = 0


def get_redirects_and_dom(results_dir, host, scheme="http", timeout=None):
    # A file used throughout to to write redirect info to.
    # We can try to parse this later, but it's easy to do it now
    redirect_file_name = os.path.join(results_dir, "redirects.csv")
    redirect_file = open(redirect_file_name, 'w')

    def save_redirect_data(*args):
        redirect_file.write(str(time.time()) + ",")
        redirect_file.write(",".join(str(x) for x in args))
        redirect_file.write("\n")
        redirect_file.flush()

    # Environment variable are inherited by Chrome when its started.
    # SSLKEYLOGFILE stores TLS secrets so that we can parse the HTTPS traffic
    # in the pcaps.
    os.environ['SSLKEYLOGFILE'] = os.path.join(results_dir, "keys/keys.pms")

    # 'performance' logging allows us to get info about network requests
    caps = DesiredCapabilities.CHROME
    caps['loggingPrefs'] = {'performance': 'ALL'}
    driver = webdriver.Chrome('./chromedriver', desired_capabilities=caps)

    driver.set_window_size(1920, 1500)
    if timeout is not None:
        driver.set_page_load_timeout(timeout)
    driver.delete_all_cookies()

    # make a request to that domain
    try:
        driver.get(scheme + "://" + host)
    except TimeoutException:
        print("TIMEOUT on", host)
        save_redirect_data("timeout", "?", "?", "?", "?")

    time.sleep(0.25)

    # save screenshot
    driver.save_screenshot(os.path.join(results_dir, "screenshot.png"))

    # save DOM
    html = driver.execute_script("return document.documentElement.outerHTML")
    with open(os.path.join(results_dir, "dom.html"), 'w') as dom_file:
        dom_file.write(html)

    #save final URL
    with open(os.path.join(results_dir, "final_urls.txt"), 'w') as final_url:
        final_url.write(str(driver.current_url))
        save_redirect_data("final", "?", "?", "?", driver.current_url)

    # save body text
    text = driver.find_elements(By.XPATH, '//body')[0].text
    with open(os.path.join(results_dir, "text.txt"), 'w') as text_file:
        text_file.write(text)

    # Get the relevant network logs
    timestamps = []
    network_requests = []
    for log in driver.get_log('performance'):
        msg = log['message']
        log_val = json.loads(msg)

        params = log_val['message']['params']

        if log_val['message']['method'] == "Network.requestWillBeSent":
            #pprint(log_val['message'])
            timestamps.append(int(log['timestamp']))
            network_requests.append(log_val['message'])

            typ = params['type']
            loc = params['request']['url']
            frameId = params.get('frameId')
            reason = params.get('initiator', dict()).get('type', "UNKNOWN")
            operation = 'load'

            if 'redirectResponse' in params:
                reason = params['redirectResponse']['status']
                operation = 'redirect'

            save_redirect_data(operation, frameId, reason, typ, loc)

        elif log_val['message']['method'] == "Page.frameNavigated":
            if 'frame' not in params:
                continue

            frame = params['frame']
            parentId = frame.get('parentId')
            url = frame.get('url')
            frameId = frame.get('id')
            save_redirect_data('navigated', frameId, parentId, url)

        elif log_val['message']['method'] == "Page.frameScheduledNavigation":
            frameId = params.get('frameId')
            reason = params.get('reason')
            url = params.get('url')
            save_redirect_data('redirect', frameId, reason, url)

    driver.quit()

    # sort the relevant logs
    sorted_ids = sorted(range(len(timestamps)), key=lambda x: timestamps[x])
    sorted_nr = [network_requests[i] for i in sorted_ids]

    # Write all network requests
    with open(os.path.join(results_dir, "request_logs.json"), 'w') as outfile:
        for x in sorted_nr:
            json.dump(x, outfile)
            outfile.write("\n")

    redirect_chain = []
    type_chain = []

    if sorted_nr:
        redirect_chain.append(sorted_nr[0]['params']['documentURL'])
        init_frame_id = sorted_nr[0]['params'].get('frameId')
        type_chain.append(None)

    for x in sorted_nr:
        headers = x['params']['request']['headers']
        documentURL = x['params']['documentURL']
        cur_frame_id = x['params']['frameId']
        redir_type = None

        if documentURL not in redirect_chain:
            # an referer based redirect
            referer = '--'
            if 'Referer' in headers:
                referer = headers['Referer']

                if referer in redirect_chain and cur_frame_id == init_frame_id:
                    redir_type = x['params']['initiator']['type']
                    type_chain.append(redir_type)
                    redirect_chain.append(documentURL)

    with open(os.path.join(results_dir, "page_redirs.txt"), 'w') as outfile:
        for x in range(0, len(redirect_chain)):
            outfile.write("{},{}\n".format(redirect_chain[x], type_chain[x]))


def fetch_wrapper(host, results_dir, scheme):
    global n_processed

    n_processed += 1

    print("Processing", "[{}/{}]".format(n_processed, n_queued), host)
    sys.stdout.flush()

    timeout = DEFAULT_TIMEOUT_S
    if host.startswith("*"):
        timeout = None
        host = host[1:]

    # Using this allows us to have 'hosts' that are actually full paths,
    # which is useful for testing if nothing else.
    filehost = host.replace("/", "_").replace(" ", "_")
    host_dir = os.path.join(results_dir, filehost)
    for d in ["screenshots", "DOM", "final_urls", "redirects", "keys"]:
        os.makedirs(os.path.join(host_dir, d), exist_ok=True)

    try:
        get_redirects_and_dom(host_dir, host, scheme=scheme, timeout=timeout)
    except TimeoutException:
        print("LATE TIMEOUT on", host)
        sys.stdout.flush()
        return host, "TIMEOUT"
    except Exception as e:
        print("ERROR while collecting data for:", host)
        sys.stdout.flush()
        traceback.print_exc()
        return host, str(e)
    return host, None


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--hosts_file', default=DEFAULT_HOSTS_FILE,
                        type=argparse.FileType('r'),
                        help="Alternate hosts.txt filename.")
    parser.add_argument('-s', '--scheme', default="http",
                        help="Initial scheme to use for URLs. Only use in "
                             "special circumstances")
    parser.add_argument('results_dir',
                        help="Directory to output results in to.")
    return parser.parse_args()


def main():
    global n_queued

    args = get_args()

    results_dir = args.results_dir
    web_hosts = []

    for line in args.hosts_file:
        if line.lstrip().startswith("#"):
            continue
        web_hosts.append(line.strip("\n").strip(" "))

    n_queued = len(web_hosts)
    futures = []

    n_ok = 0
    n_error = 0

    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as e:
        for i, host in enumerate(web_hosts):
            print("Queueing", "[{}/{}]".format(i + 1, len(web_hosts)), host)
            sys.stdout.flush()
            futures.append(
                e.submit(fetch_wrapper, host, results_dir, args.scheme))

        for i, future in enumerate(as_completed(futures)):
            host, error = future.result()
            if not error:
                n_ok += 1
            else:
                n_error += 1

            if error and error != "TIMEOUT":
                print("Unexpected error on", host, ":", error)

    print("Final result:", n_ok, "successes,", n_error, "failures")


if __name__ == "__main__":
    main()

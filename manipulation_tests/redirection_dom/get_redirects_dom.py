import argparse
import json
import logging
import os
import os.path
import sys
import time
import traceback

from concurrent.futures import ThreadPoolExecutor, as_completed

from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By

from chrome_killa import start_chrome_killa

# TODO - when sites timeout (from set_page_load_timeout) they throw an
#        exception that causes a return to main. That means that it doesn't
#        write any partial results that may be available.

DEFAULT_HOSTS_FILE = "hosts.txt"

# How long to wait for a page to finish loading
DEFAULT_TIMEOUT_S = 20

# Number of threads to run simultaneously?
# This makes timeouts go through the roof, though...
NUM_WORKERS = 2

# These are just used for status updating. I don't protect them with locks
# because they're just for human feedback.
n_processed = 0
n_queued = 0


LOG_FORMAT = (
    "%(asctime)s %(levelname)-7s %(name)-8s %(funcName)-15s %(message)s")


logger = logging.getLogger("doms")


def query_host(results_dir, host, scheme="http", timeout=None):
    start = time.time()

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
    caps['max_duration'] = 180  # Kill test after 3 minutes of wedge, not 10.
    driver = webdriver.Chrome('./chromedriver', desired_capabilities=caps)

    driver.set_window_size(1920, 1500)
    if timeout is not None:
        driver.set_page_load_timeout(timeout)
    driver.delete_all_cookies()

    mid1 = time.time()
    diff = mid1 - start
    logger.info(".. Started Chrome in %.1f seconds for %s", diff, host)

    # make a request to that domain
    try:
        driver.get(scheme + "://" + host)
    except TimeoutException:
        logger.info(".. TIMEOUT on %s", host)
        save_redirect_data("timeout", "?", "?", "?", "?")

    mid2 = time.time()
    diff = mid2 - mid1
    logger.info(".. Fetched %s in %.1f seconds", host, diff)

    time.sleep(0.25)

    # save screenshot
    #driver.save_screenshot(os.path.join(results_dir, "screenshot.png"))

    mid3 = time.time()
    diff = mid3 - mid2
    #logger.info(".. Screenshotted %s in %.1f seconds", host, diff)

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

    mid4 = time.time()
    diff = mid4 - mid3
    logger.info(".. Perf dumped %s in %.1f seconds", host, diff)

    # save DOM
    html = driver.execute_script("return document.documentElement.outerHTML")
    with open(os.path.join(results_dir, "dom.html"), 'w') as dom_file:
        dom_file.write(html.encode('utf-8'))

    #save final URL
    with open(os.path.join(results_dir, "final_urls.txt"), 'w') as final_url:
        final_url.write(str(driver.current_url))
        save_redirect_data("final", "?", "?", "?", driver.current_url)

    # save body text
    text = driver.find_elements(By.XPATH, '//body')[0].text
    with open(os.path.join(results_dir, "text.txt"), 'w') as text_file:
        text_file.write(text)

    mid5 = time.time()
    diff = mid5 - mid4
    logger.info(".. Dumped %s in %.1f seconds", host, diff)

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
        cur_frame_id = x['params'].get('frameId')
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

    end = time.time()
    pdiff = end - mid5
    diff = end - start
    logger.info(".. Completed %s in %.1f seconds (%.1f)", host, diff, pdiff)


def fetch_wrapper(host, results_dir, scheme):
    global n_processed

    # Stall a bit so we're no in sync together if we're just getting started.
    if n_processed < NUM_WORKERS:
        time.sleep(n_processed * 5)

    n_processed += 1

    logger.info("[%2d/%2d] Processing %s", n_processed, n_queued, host)
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
        query_host(host_dir, host, scheme=scheme, timeout=timeout)
    except TimeoutException:
        logger.warning("LATE TIMEOUT on %s", host)
        sys.stdout.flush()
        return host, "TIMEOUT"
    except WebDriverException as e:
        logger.warning("WEBDRIVER EXCEPTION on %s (%s)", host, e)
        sys.stdout.flush()
        return host, "WEBDRIVER"
    except Exception as e:
        logger.error("ERROR while collecting data for: %s", host)
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
    global n_queued

    args = get_args()

    # DEBUG gives you a bunch of selenium details
    setup_logging(False)

    start_chrome_killa()

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
            logger.info("Queueing [%d/%d] %s", i + 1, len(web_hosts), host)
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
                logger.error("Unexpected error on %s: %s", host, error)

    logger.info("Final result: %d successes, %d failures", n_ok, n_error)


if __name__ == "__main__":
    main()

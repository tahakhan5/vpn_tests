import json
import os
import os.path
import sys
import time
import traceback

from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By

# TODO - when sites timeout (from set_page_load_timeout) they throw an
#        exception that causes a return to main. That means that it doesn't
#        write any partial results that may be available.


def get_redirects_and_dom(results_dir, host):
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
    driver.set_page_load_timeout(10)
    driver.delete_all_cookies()

    # make a request to that domain
    try:
        driver.get("http://" + host)
    except TimeoutException:
        print("TIMEOUT on", host)
        return

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
            frameId = params['frameId']
            reason = params['initiator']['type']
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

    redirect_chain.append(sorted_nr[0]['params']['documentURL'])
    init_frame_id = sorted_nr[0]['params']['frameId']
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

    # Header-based redirects are shown within the other logs for those
    # motivated to find them :-P
    #redir_history = []
    #redir_codes = []
    #r = requests.get("http://"+host)

    #for x in r.history:
    #    redir_history.append(x.url)
    #    redir_codes.append(x.status_code)
    #redir_history.append(r.url)
    #redir_codes.append(r.status_code)

    #with open(
    #        os.path.join(results_dir, "header_redirs.txt"), 'w') as outfile:
    #    for x in range(0, len(redir_history)):
    #        outfile.write(str(redir_history[x])+","+str(redir_codes[x])+"\n")


def main():

    results_dir = sys.argv[1]
    web_hosts = []

    with open("hosts.txt") as f:
        for line in f:
            if line.startswith("#"):
                continue
            web_hosts.append(line.strip("\n").strip(" "))

    for i, host in enumerate(web_hosts):
        print("Processing", "[{}/{}]".format(i + 1, len(web_hosts)), host)

        # Using this allows us to have 'hosts' that are actually full paths,
        # which is useful for testing if nothing else.
        filehost = host.replace("/", "_").replace(" ", "_")
        host_dir = os.path.join(results_dir, filehost)
        for d in ["screenshots", "DOM", "final_urls", "redirects", "keys"]:
            os.makedirs(os.path.join(host_dir, d), exist_ok=True)

        try:
            get_redirects_and_dom(host_dir, host)
        except Exception as e:
            print("ERROR while collecting data for:", host)
            traceback.print_exc()
        sys.stdout.flush()


if __name__ == "__main__":
    main()

import sys
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
import json
import subprocess
import requests
import time



def get_redirects_and_dom(results_dir, host):

    # make a request to that domain
    caps = DesiredCapabilities.CHROME
    caps['loggingPrefs'] = {'performance': 'ALL'}
    driver = webdriver.Chrome('./chromedriver', desired_capabilities=caps)
    driver.set_window_size(1920, 1500)
    driver.set_page_load_timeout(10)

    driver.get("http://"+host)
    time.sleep(0.25)

    # save screenshot
    driver.save_screenshot(results_dir+"screenshots/"+host+".png")

	# save DOM
    html = driver.execute_script("return document.documentElement.outerHTML")
    dom_file = open(results_dir+"DOM/"+host+".html",'w')
    dom_file.write(html)
    dom_file.close()

	#save final URL
    final_url = open(results_dir+"final_urls/"+host+".txt",'w')
    final_url.write(str(driver.current_url))
    final_url.close()

	# save body text
    text = driver.find_elements(By.XPATH, '//body')[0].text
    text_file = open(results_dir+"text/"+host+".txt",'w')
    text_file.write(text)
    text_file.close()

    # Get the relevant network logs
    timestamps = []
    network_requests = []
    for log in driver.get_log('performance'):
        msg = log['message']
        log_val = json.loads(msg)
        if log_val['message']['method'] == "Network.requestWillBeSent":
            timestamps.append(int(log['timestamp']))
            network_requests.append(log_val['message'])
    
    # sort the relevant logs
    sorted_ids = sorted(range(len(timestamps)),key=lambda x:timestamps[x])
    sorted_nr = [network_requests[i] for i in sorted_ids]

    subprocess.call(['mkdir', results_dir+"redirects/"+host])

    # Write all network requests
    with open(results_dir+"redirects/"+host+"/request_logs.json", 'w') as outfile:
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
        req_params = x['params']['request']
        documentURL = x['params']['documentURL']
        cur_frame_id = x['params']['frameId']
        redir_type = None

        if documentURL not in redirect_chain:        
            # an referer based redirect        
            referer = '--'
            if 'Referer' in headers:
                referer =headers['Referer']

                if referer in redirect_chain and cur_frame_id == init_frame_id:
                    redir_type = x['params']['initiator']['type']
                    type_chain.append(redir_type)
                    redirect_chain.append(documentURL)
    


    with open(results_dir+"redirects/"+host+"/page_redirs.txt", 'w') as outfile:
        for x in range(0, len(redirect_chain)):
            outfile.write(str(redirect_chain[x])+","+str(type_chain[x])+"\n")
    
    # Get any header basesd redirects
    redir_history = []
    redir_codes = []
    r = requests.get("http://"+host)

    for x in r.history:
        redir_history.append(x.url)
        redir_codes.append(x.status_code)
    redir_history.append(r.url)
    redir_codes.append(r.status_code)

    with open(results_dir+"redirects/"+host+"/header_redirs.txt", 'w') as outfile:
            for x in range(0, len(redir_history)):
                outfile.write(str(redir_history[x])+","+str(redir_codes[x])+"\n")


def main():
    
    results_dir = sys.argv[1]
    subprocess.call(["mkdir", results_dir+"screenshots", results_dir+"DOM", results_dir+"text", results_dir+"final_urls", results_dir+"redirects"])
    web_hosts = []

    with open("hosts.txt") as f:
        for line in f:
            web_hosts.append(line.strip("\n").strip(" "))
    for host in web_hosts:
        try:
            get_redirects_and_dom(results_dir, host)
        except Exception as e:
            print("ERROR while collecting data for: "+host)

if __name__ == "__main__":
    main()

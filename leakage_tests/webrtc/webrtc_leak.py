import json
import subprocess
import sys
import time

from queue import Queue, Empty
from threading import Thread

from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.options import Options

import scapy.all as sc

test_completed = False


# write a a packet to the file
def write_to_file(file_name, raw_packet):
    sc.wrpcap(file_name, raw_packet, append=True)


# continously smiff packets and put them in a queue that is polled
def sniffing_tread(interface, pkt_queue):
    sc.sniff(iface=interface, prn=lambda x: pkt_queue.put(x))


# Establoishes a simple WebRTCDataConn and makes a STUN request
def test_1(ips_file, source_file):
    global test_completed
    d = DesiredCapabilities.CHROME
    d['loggingPrefs'] = {'browser': 'ALL'}
    driver = webdriver.Chrome('./chromedriver')
    for x in range(1, 10):
        driver.get("http://localhost:8080")
        time.sleep(0.5)
        html = driver.page_source

    src_file = open(source_file, 'w')
    src_file.write(html)

    with open(ips_file, 'w') as json_file:
        for entry in driver.get_log('browser'):
            if entry['source'] == 'console-api':
                json.dump(entry, json_file)

    test_completed = True


# This test establishes a p2p based RTC connection
def test_2():

    global test_completed
    chrome_options = Options()
    chrome_options.add_argument("user-data-dir=./ChromeProfile/")
    driver = webdriver.Chrome('./chromedriver', chrome_options=chrome_options)

    driver.get("https://kevingleason.me/SimpleRTC/minivid.html")
    driver.find_element_by_id('username').send_keys('user_1')
    driver.find_element_by_class_name('fa-sign-in').click()
    driver.find_element_by_name('number').send_keys('user_2')
    driver.find_element_by_class_name('fa-phone-square').click()

    driver.execute_script(
        '''window.open("'''
        '''https://kevingleason.me/SimpleRTC/minivid.html","_blank");''')
    windows = driver.window_handles
    driver.switch_to.window(windows[1])
    driver.find_element_by_id('username').send_keys('user_2')
    driver.find_element_by_class_name('fa-sign-in').click()
    driver.find_element_by_name('number').send_keys('user_1')
    driver.find_element_by_class_name('fa-phone-square').click()
    time.sleep(15)
    test_completed = True


def read_pacp_file(pcap_file):
    tcpdump_response = subprocess.run(
        ['tshark', '-r', pcap_file], stdout=subprocess.PIPE)
    output = tcpdump_response.stdout
    if b"STUN" in output or b"MAPPED-ADDRESS" in output:
        print('WebRTC based IP Leakage found')


def main():
    global test_completed
    output_file = sys.argv[1] + 'captured_rtc.pcap'
    console_ip = sys.argv[1] + 'leaked_ips.json'
    source_file = sys.argv[1] + 'page_source.html'

    capture_interface = 'en0'
    packet_list = []
    packets = Queue()

    # start siffing packets on the respective interface
    sniffer = Thread(target=sniffing_tread, args=(capture_interface, packets,))
    sniffer.daemon = True
    sniffer.start()

    # run test without threading
    rtc_call_thread_1 = Thread(target=test_1, args=(console_ip, source_file,))
    rtc_call_thread_1.start()

    # Webrtc test number two which connects to websites
    # rtc_call_thread_2 = Thread(target=test_2)
    # rtc_call_thread_2.start()

    while True:
        try:
            pkt = packets.get()
            write_to_file(output_file, pkt)
            packet_list.append(pkt)
            if test_completed:
                break
        except Empty:
            pass

    # read the capture dump to evaluate leakage
    read_pacp_file(output_file)


if __name__ == '__main__':
    main()

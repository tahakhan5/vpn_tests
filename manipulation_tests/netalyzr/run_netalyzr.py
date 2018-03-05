import sys
import subprocess
import csv
import requests

def run_netalyzr():
    result_out = subprocess.Popen(['java','-jar', 'NetalyzrCLI.jar'], stdout=subprocess.PIPE)
    std_output = result_out.communicate()[0].decode('ASCII', errors='ignore')
    results_url = std_output.split("results available at:")[-1].strip("\n")
    return results_url

def dump_results(url):
    json_link = url.replace("/summary/","/json/")
    r = requests.get(json_link)
    output_json = open(sys.argv[1]+"results.json", 'wb')
    output_json.write(r.content)
    output_json.close()
    return

def main():
    result_url = run_netalyzr()
    link_file = open(sys.argv[1]+"results_link.txt", 'w')
    link_file.write(result_url+"\n")
    link_file.close()
    dump_results(result_url)
if __name__ == "__main__":
    main()

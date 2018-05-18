import os.path
import sys
import subprocess
import requests


def run_netalyzr():
    result_out = subprocess.Popen(
        ['java',
         '-jar', 'NetalyzrCLI.jar',
         '-XX:+IgnoreUnrecognizedVMOptions',
         '--add-modules', 'java.xml.bind'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = result_out.communicate(timeout=1200)  # Kill it after 20 min
    except subprocess.TimeoutExpired:
        result_out.kill()
        outs, errs = result_out.communicate()
        sys.stderr.write("Had to kill Netalyzr...\n")

    with open(os.path.join(sys.argv[1], "netalyzr_stdout.out"), 'wb') as f:
        f.write(out)
    with open(os.path.join(sys.argv[1], "netalyzr_stderr.out"), 'wb') as f:
        f.write(err)
    std_output = out.decode('ASCII', errors='ignore')
    results_url = std_output.split("results available at:")[-1].strip("\n")
    return results_url


def dump_results(url):
    json_link = url.replace("/summary/", "/json/")
    r = requests.get(json_link)
    output_json = open(os.path.join(sys.argv[1], "results.json"), 'wb')
    output_json.write(r.content)
    output_json.close()
    return


def main():
    result_url = run_netalyzr()
    link_file = open(os.path.join(sys.argv[1], "results_link.txt"), 'w')
    link_file.write(result_url + "\n")
    link_file.close()
    dump_results(result_url)


if __name__ == "__main__":
    main()

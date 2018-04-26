#!/bin/bash

# A common file to hold test wrapper functions
# We use it across run_tests.sh and run_tests_auto.sh

test_webrtc_leak() {
    unzip -q ChromeProfile.zip

    python3 -m http.server 8080 &
    export HTTP_SERVER_PID=$!

    python3 webrtc_leak.py $1
    kill -s TERM $HTTP_SERVER_PID

    rm -rf ChromeProfile
}

test_dns_manipulation() {
    ./checkdns.sh
}

test_netalyzr() {
    python3 run_netalyzr.py $1
}

test_dom_redirection() {
    python3 get_redirects_dom.py $1
}

test_ssl_collection() {
    python3 cert_collector.py $1
}

test_backconnect() {
    ./backconnect/backconnect -o $1
}

test_backconnect_nov6() {
    # We disable IPv6 during the auto tests
    ./backconnect/backconnect -6 -o $1
}

test_infra_infer() {
    [[ -e ./infrastructure_inference/creds.json ]] || fetch_creds

    ./infrastructure_inference/run_tests \
        -o $1 infrastructure_inference/creds.json
}

test_recursive_dns_origin() {
    datestamp=$(date '+%y%m%d-%H%M%S')
    dig cvst-$datestamp-${TAG//_/-}.homezone-project.eu > $1/lookup.out
}

test_ipv6_leakage() {
    python3 ./leakage_tests/ipv6/ipv6_leak.py \
        -r leakage_tests/ipv6/v6_resolutions.csv $1
}

test_tun_fail() {
    python3 run_test.py -o $1/tunnel_failure_log
}

#!/bin/bash

usage() {
    if [[ "$@" ]]; then
        echo -e "ERROR: $@\n" >&2
    fi

    cat - <<EOF >&2
You should not be calling this script by hand.

It is designed to be called by scripts that iterate over multiple VPN endpoints.

(...but if you must know, the usage is: $0 VPN_NAME VPN_LOC_TAG )

EOF
    exit 1
}

NUM_ARGS=2

if [[ "$#" -ne $NUM_ARGS ]]; then
    usage "Invalid Arguments"
fi

if [[ $(whoami) != 'root' ]]; then
    echo "This script must run as root! (precede command with 'sudo')" >&2
    exit 1
fi

### determine the root directory -- hackish but works with OS X and bash.
pushd $(dirname $BASH_SOURCE) > /dev/null
ROOT=$(pwd)
popd >/dev/null
###

source $ROOT/venv/bin/activate

# Functions for uploading results and retrieving API keys.
source $ROOT/includes/transfer_func.sh
# Additional helper functions for cleanly running tests.
source $ROOT/includes/helper_funcs.sh

DEFAULT_DIR=`pwd`

# collect information about the vpn service
VPN_NAME=$1
VPN_LOC_TAG=$2

# create a tag for labeling purposes
PATH_SAFE_VPN_NAME=$(echo "${VPN_NAME// /_}" | clean_str)
PATH_SAFE_VPN_LOC_TAG=$(echo "${VPN_LOC_TAG// /_}" | clean_str)
TAG=${PATH_SAFE_VPN_NAME}_${PATH_SAFE_VPN_LOC_TAG}

# fetch the git commit info
COMMIT=$(cd $ROOT; git rev-parse --verify HEAD)

################################################################################

# create respective directories for results
RESULTS_DIR=$DEFAULT_DIR/$TAG"_results/"
mkdir -p $RESULTS_DIR

# Yeah, I dunno what happened here, but I know I'm really hesitant to rm -rf
# anything using root's user. Shame if $RESULTS_DIR were to be unset for some
# reason...
#rm -rf $RESULTS_DIR/*

CONFIG_DIR=$RESULTS_DIR/configs
mkdir -p $CONFIG_DIR

TRACES_DIR=$RESULTS_DIR/network_traces
mkdir -p $TRACES_DIR

################################################################################

# write the basic info to a file
echo NAME:$VPN_NAME >> $RESULTS_DIR$TAG"_info"
echo CITY:$VPN_CITY >> $RESULTS_DIR$TAG"_info"
echo LOC_TAG:$VPN_LOC_TAG >> $RESULTS_DIR$TAG"_info"
echo COMMIT:$COMMIT >> $RESULTS_DIR$TAG"_info"

# This can't be done here since the script is in a loop
## save the default ifconfig and dns nsconfig file
#ifconfig -v > $CONFIG_DIR$TAG"_ifconfig_default"
#cat /etc/resolv.conf > $CONFIG_DIR$TAG"_resolv_default"

# We no longer capture an overall pcap because it doubles our result's size.

# save  ifconfig and dns config files after the VPN has been connected
#
# XXX: Note from Joe: Just FYI, infrastructure_inference has already been
#      recording this.
ifconfig -v > $CONFIG_DIR/$TAG"_ifconfig_connected"
cat /etc/resolv.conf > $CONFIG_DIR/$TAG"_resolv_connected"
EXTERNAL_VPN_IP=$(get_external_ip)
echo $EXTERNAL_VPN_IP > $CONFIG_DIR/$TAG"_external_ip"

##############################################################################

test_dns_leakage() {
    pushd ./leakage_tests/dns/ > /dev/null
    python3 -u dns_leak_test.py $1 | tee $1/dns_leak_log
    popd > /dev/null
}

test_webrtc_leak() {
    pushd ./leakage_tests/webrtc/ > /dev/null

    unzip -q ChromeProfile.zip

    python3 -m http.server 8080 &
    export HTTP_SERVER_PID=$!

    python3 webrtc_leak.py $1 | tee $1/rtc_leak_log
    kill -s TERM $HTTP_SERVER_PID

    rm -rf ChromeProfile

    popd > /dev/null
}

test_dns_manipulation() {
    pushd ./manipulation_tests/dns/ > /dev/null
    ./checkdns.sh > $1/dns_manipulation_log
    popd > /dev/null
}

test_netalyzr() {
    pushd ./manipulation_tests/netalyzr/ > /dev/null
    python3 run_netalyzr.py $1
    popd > /dev/null
}

test_dom_redirection() {
    pushd ./manipulation_tests/redirection_dom/ > /dev/null
    python3 get_redirects_dom.py $1 | tee $1/redirection_dom_log
    popd > /dev/null
}

test_ssl_collection() {
    pushd ./manipulation_tests/ssl/ > /dev/null
    python3 cert_collector.py $1 | tee $1/ssl_collector_log
    popd > /dev/null
}

test_backconnect() {
    # We disable IPv6 for time.
    # Raw openvpn won't protect you against IPv6 leakage anyway.
    ./backconnect/backconnect -6 -o $1
}

test_infra_infer() {
    [[ -e ./infrastructure_inference/creds.json ]] || fetch_creds

    ./infrastructure_inference/run_tests \
        -o $1 infrastructure_inference/creds.json
}

test_ipv6_leakage() {
    python3 ./leakage_tests/ipv6/ipv6_leak.py \
        -r leakage_tests/ipv6/v6_resolutions.csv $1
}

test_tunnel_failure() {
    pushd ./leakage_tests/tunnel_failure/ > /dev/null
    python3 run_test.py -o $TUNNEL_FAILURE_DIR"tunnel_failure_log"
    popd > /dev/null
}

test_recursive_dns_origin() {
    datestamp=$(date '+%y%m%d-%H%M%S')
    dig cvst-$datestamp-${TAG//_/-}.homezone-project.eu > $1/lookup.out
}


# Run the tests we want, while capturing pcaps and giving feedback to the user

info "Disabling IPv6 for the duration of the test."
networksetup -setv6off Ethernet

info_box "Executing leakage tests"
run_test test_webrtc_leak rtc_leak "WEBRTC LEAK"

info_box "Executing manipulation tests"
run_test test_dns_manipulation dns_manipulation "DNS MANIPULATION"
time run_test test_dom_redirection dom_redirection "DOM & REDIRECTION"
time run_test test_ssl_collection ssl_collection "SSL"

info_box "Executing infrastructure tests"
run_test test_recursive_dns_origin recursive_dns_origin "RECURSIVE DNS"
run_test test_backconnect backconnect "BACKCONNECT"
run_test test_infra_infer infrastructure_inference "INFRASTRUCTURE INFERENCE"

## Keep these tests last
info_box "Executing final tests"
run_test test_netalyzr netalyzr "NETALYZR"

# These stay disabled
# OpenVPN WILL leak DNS and IPv6 unless you work around it.
#run_test test_dns_leakage dns_leak "DNS LEAKAGE TEST"
#run_test test_ipv6_leakage ipv6_leakage "IPv6 LEAKAGE"  # OpenVPN WILL leak

# Tunnel failure is just a pain in the butt in our case.
#run_test test_tunnel_failure tunnel_failure "TUNNEL FAILURE"

################################################################################

info "Re-enabling IPv6."
networksetup -setv6automatic Ethernet
info "Waiting a bit for IPv6 recovery."
sleep 5

info "TESTS COMPLETE"

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

rm -rf $ROOT/*_results/
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

################################################################################

# create respective directories for results
RESULTS_DIR=$DEFAULT_DIR/$TAG"_results/"
mkdir -p $RESULTS_DIR

CONFIG_DIR=$RESULTS_DIR/configs
mkdir -p $CONFIG_DIR

TRACES_DIR=$RESULTS_DIR/network_traces
mkdir -p $TRACES_DIR

################################################################################

# write the basic info to a file
echo NAME:$VPN_NAME >> $RESULTS_DIR$TAG"_info"
echo CITY:$VPN_CITY >> $RESULTS_DIR$TAG"_info"
echo LOC_TAG:$VPN_LOC_TAG >> $RESULTS_DIR$TAG"_info"

# This can't be done here since the script is in a loop
## save the default ifconfig and dns nsconfig file
#ifconfig -v > $CONFIG_DIR$TAG"_ifconfig_default"
#cat /etc/resolv.conf > $CONFIG_DIR$TAG"_resolv_default"

# run tcp dump instance which collects the complete trace of VPN service
DUMP_FILE=_dump_complete.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR/$TAG$DUMP_FILE &
export COMPLETE_DUMP_PID=$!

# save  ifconfig and dns config files after the VPN has been connected
#
# XXX: Note from Joe: Just FYI, infrastructure_inference has already been
#      recording this.
ifconfig -v > $CONFIG_DIR/$TAG"_ifconfig_connected"
cat /etc/resolv.conf > $CONFIG_DIR/$TAG"_resolv_connected"

##############################################################################

test_dns_leakage() {
    pushd ./leakage_tests/dns/ > /dev/null
    python3 dns_leak_test.py $1 | tee $1/dns_leak_log
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

test_backconnect() {
    ./backconnect/backconnect -o $1
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

echo "#################--EXECUTING LEAKAGE TESTS--############################"
run_test test_dns_leakage dns_leak "DNS LEAKAGE TEST"
run_test test_webrtc_leak rtc_leak "WEBRTC LEAK"
run_test test_ipv6_leakage ipv6_leakage "IPv6 LEAKAGE"

echo "##############--EXECUTING MANIPULATION TESTS--##########################"
run_test test_dns_manipulation dns_manipulation "DNS MANIPULATION"
run_test test_netalyzr netalyzr "NETALYZR"
run_test test_dom_redirection dom_redirection "DOM & REDIRECTION"

echo "#############--EXECUTING INFRASTRUCTURE TESTS--#########################"
run_test test_recursive_dns_origin recursive_dns_origin "RECURSIVE DNS"
run_test test_backconnect backconnect "BACKCONNECT"
run_test test_infra_infer infrastructure_inference "INFRASTRUCTURE INFERENCE"

# Keep this test last
run_test test_tunnel_failure tunnel_failure "TUNNEL FAILURE"


################################################################################

echo "-------------------------------------------------------------------------"
echo "KILLING CAPTURES"
echo "-------------------------------------------------------------------------"

# Kill the process which is collecting the complete dump
#kill -9 $COMPLETE_DUMP_PID
kill -s TERM $COMPLETE_DUMP_PID

wait

echo "-------------------------------------------------------------------------"
echo "Waiting for internet to recover."

wait_until_connected

echo -e "\nTransferring results"
echo "-------------------------------------------------------------------------"

transfer_file $TAG $RESULTS_DIR

echo "************************************************************************"
echo "TESTS COMPLETED."
echo "************************************************************************"

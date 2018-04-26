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
# Test functions
source $ROOT/includes/test_funcs.sh

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

# Run the tests we want, while capturing pcaps and giving feedback to the user

info "Disabling IPv6 for the duration of the test."
networksetup -setv6off Ethernet

info_box "Executing leakage tests"
run_test test_webrtc_leak rtc_leak ./leakage_tests/webrtc/

info_box "Executing manipulation tests"
run_test test_dns_manipulation dns_manipulation ./manipulation_tests/dns/
run_test test_dom_redirection dom_redirection ./manipulation_tests/redirection_dom/
run_test test_ssl_collection ssl_collection ./manipulation_tests/ssl/

info_box "Executing infrastructure tests"
run_test test_recursive_dns_origin recursive_dns_origin
run_test test_backconnect_nov6 backconnect
run_test test_infra_infer infrastructure_inference

## Keep these tests last
info_box "Executing final tests"
run_test test_netalyzr netalyzr ./manipulation_tests/netalyzr/

# These stay disabled
# OpenVPN WILL leak DNS and IPv6 unless you work around it.
#run_test test_dns_leakage dns_leak
#run_test test_ipv6_leakage ipv6_leakage  # OpenVPN WILL leak
# Tunnel failure isn't interesting when you control the tunnel.
#run_test test_tunnel_failure tunnel_failure

################################################################################

info "Re-enabling IPv6."
networksetup -setv6automatic Ethernet
info "Waiting a bit for IPv6 recovery."
sleep 5

info "TESTS COMPLETE"

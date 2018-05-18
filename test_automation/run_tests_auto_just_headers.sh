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
pushd $(dirname $BASH_SOURCE)/.. > /dev/null
ROOT=$(pwd)
popd >/dev/null
###

source $ROOT/venv/bin/activate
pip3 -qq install -r $ROOT/requirements.txt

# Functions for uploading results and retrieving API keys.
source $ROOT/includes/transfer_func.sh
# Additional helper functions for cleanly running tests.
source $ROOT/includes/helper_funcs.sh
# Test functions
source $ROOT/includes/test_funcs.sh

# Sometimes, it takes some time for openvpn to settle. We don't have a lot of
# time, but give it a chance.
info "Waiting until connection is active again..."
wait_until_connected 10
if [[ $? -ne 0 ]]; then
    info "Wasn't active in time. Skipping."
    exit 1
fi

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

log_checkpoint "auto_start" "AUTO"

################################################################################

# create respective directories for results
RESULTS_DIR=$DEFAULT_DIR/results/$TAG
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
echo NAME:$VPN_NAME >> $RESULTS_DIR/info
echo CITY:$VPN_CITY >> $RESULTS_DIR/info
echo LOC_TAG:$VPN_LOC_TAG >> $RESULTS_DIR/info
echo COMMIT:$COMMIT >> $RESULTS_DIR/info
echo STARTTIME:$(date -u -R) >> $RESULTS_DIR/info

# This can't be done here since the script is in a loop
## save the default ifconfig and dns nsconfig file
#ifconfig -v > $CONFIG_DIR/ifconfig_default
#cat /etc/resolv.conf > $CONFIG_DIR/resolv_default"

# We no longer capture an overall pcap because it doubles our result's size.

# save  ifconfig and dns config files after the VPN has been connected
#
# XXX: Note from Joe: Just FYI, infrastructure_inference has already been
#      recording this.
ifconfig -v > $CONFIG_DIR/ifconfig_connected
cat /etc/resolv.conf > $CONFIG_DIR/resolv_connected
EXTERNAL_VPN_IP=$(get_external_ip)
echo $EXTERNAL_VPN_IP > $CONFIG_DIR/external_ip

##############################################################################

log_checkpoint "auto_testing"

# Run the tests we want, while capturing pcaps and giving feedback to the user

info "Disabling IPv6 for the duration of the test."
networksetup -setv6off Ethernet

run_test test_bad_requests bad_requests $ROOT/manipulation_tests/badrequests/

################################################################################

echo ENDTIME:$(date -u -R) >> $RESULTS_DIR/info

info "Re-enabling IPv6."
networksetup -setv6automatic Ethernet
info "Waiting a bit for IPv6 recovery."
sleep 5

info "TESTS COMPLETE"

log_checkpoint "auto_tests_complete"

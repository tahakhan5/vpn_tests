#!/bin/bash

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
pip3 -qq install -r $ROOT/requirements.txt

# Functions for uploading results and retrieving API keys.
source $ROOT/includes/transfer_func.sh
# Additional helper functions for cleanly running tests.
source $ROOT/includes/helper_funcs.sh
# Test functions
source $ROOT/includes/test_funcs.sh

DEFAULT_DIR=`pwd`

if [[ "$1" == "JUST_TRANSFER" ]]; then
    shift 1
    info "Trying to just transfer previous results..."
    transfer_file $@ || error "Still didn't work. Please try again."
    exit
fi

if [[ "$1" == "no_v6" ]]; then
    info "Verifying (non-v6) internet connectivity..."
    if ! verify_ipv4_connectivity; then
        exit 1
    fi
    info "...you're good to go!"
    shift 1

elif [[ "$1" == "no_check" ]]; then
    info "Verifying internet connectivity..."
    if ! verify_connectivity; then
        exit 1
    fi
    info "...you're good to go!"
    shift 1

fi

# update time from the network to avoid certificate errors
ntpdate -u time.apple.com > /dev/null &

# preemptively update the permissions of the drop-off key
chmod 500 $DEFAULT_DIR/includes/dropoff_key

# fetch the git commit info
COMMIT=$(get_commit)

# pull changes to repo if necessary
if [[ "$1" == "dev" ]]; then
    warning "Running in DEV mode..."
else
    update_repository
    NEW_COMMIT=$(get_commit)
    if [[ "$NEW_COMMIT" != "$COMMIT" ]]; then
        info "Your repository was out of date... restarting."
        exec $0 $@
    fi
fi

ensure_host_modifications_installed

# collect information about the vpn service
alert "Please enter VPN details"
read -p "Enter the name of the VPN service being tested: " VPN_NAME
read -p "Enter the country for the server you are connecting to: " VPN_COUNTRY
read -p "Enter the city you are connecting to (leave blank if unavailable): " VPN_CITY
read -p "Enter a SHORT + UNIQUE descriptor for the supposed VPN current location (e.g.  'sfo1') : " VPN_LOC_TAG
read -p "Enter YOUR first name (e.g. 'Joe'): " RUNNER_NAME

# create a tag for labeling purposes
PATH_SAFE_VPN_NAME=$(echo "${VPN_NAME// /_}" | clean_str)
PATH_SAFE_VPN_LOC_TAG=$(echo "${VPN_LOC_TAG// /_}" | clean_str)
TAG=${PATH_SAFE_VPN_NAME}_${PATH_SAFE_VPN_LOC_TAG}

log_checkpoint "start" $RUNNER_NAME

#########################################################################################

# create respective directories for results
RESULTS_DIR=$DEFAULT_DIR/results/$TAG
mkdir -p $RESULTS_DIR

CONFIG_DIR=$RESULTS_DIR/configs
mkdir -p $CONFIG_DIR

TRACES_DIR=$RESULTS_DIR/network_traces
mkdir -p $TRACES_DIR

#########################################################################################

# write the basic info to a file
echo NAME:$VPN_NAME >> $RESULTS_DIR/info
echo COUNTRY:$VPN_COUNTRY >> $RESULTS_DIR/info
echo CITY:$VPN_CITY >> $RESULTS_DIR/info
echo LOC_TAG:$VPN_LOC_TAG >> $RESULTS_DIR/info
echo COMMIT:$COMMIT >> $RESULTS_DIR/info
echo STARTTIME:$(date -u -R) >> $RESULTS_DIR/info
echo RUNNER_NAME:$RUNNER_NAME >> $RESULTS_DIR/info

# save the default ifconfig, dns nsconfig file and IP
ifconfig -v > $CONFIG_DIR/ifconfig_default
cat /etc/resolv.conf > $CONFIG_DIR/resolv_default
PRE_VPN_IP=$(get_external_ip)
echo $PRE_VPN_IP > $CONFIG_DIR/pre_vpn_ip

# prompt user to connect to the VPN service
alert "CONNECT TO THE VPN SERVICE"

while ! confirm "Are you connected to the VPN?"; do :; done

EXTERNAL_VPN_IP=$(get_external_ip)
if [[ -z "$EXTERNAL_VPN_IP" ]]; then
    warning "Your connection doesn't seem to be working..."
    confirm "Continue anyway?" || exit
elif [[ "$EXTERNAL_VPN_IP" == "$PRE_VPN_IP" ]]; then
    warning "Your IP address hasn't changed after connecting to the VPN!"
    confirm "Continue anyway?" || exit
fi

log_checkpoint "connected"

# We no longer capture an overall pcap because it doubles our result's size.

# save  ifconfig and dns config files after the VPN has been connected
#
# XXX: Note from Joe: Just FYI, infrastructure_inference has already been
#      recording this.
ifconfig -v > $CONFIG_DIR/ifconfig_connected
cat /etc/resolv.conf > $CONFIG_DIR/resolv_connected
echo $EXTERNAL_VPN_IP > $CONFIG_DIR/external_ip

log_checkpoint "testing"

##############################################################################

info_box "EXECUTING LEAKAGE TESTS"
run_test test_dns_leakage dns_leak $ROOT/leakage_tests/dns/
run_test test_webrtc_leak rtc_leak $ROOT/leakage_tests/webrtc/
run_test test_ipv6_leakage ipv6_leakage

###############################################################################

info_box "EXECUTING MANIPULATION TESTS"
run_test test_dns_manipulation dns_manipulation $ROOT/manipulation_tests/dns/
run_test test_dom_redirection dom_redirection $ROOT/manipulation_tests/redirection_dom/
run_test test_ssl_collection ssl_collection $ROOT/manipulation_tests/ssl/
run_test test_bad_requests bad_requests $ROOT/manipulation_tests/badrequests/

##############################################################################

info_box "EXECUTING INFRASTRUCTURE TESTS"
run_test test_recursive_dns_origin recursive_dns_origin
run_test test_backconnect backconnect
run_test test_infra_infer infrastructure_inference

################################################################################

# These tests should run at the end
info_box "EXECUTING END-GAME TESTS"
run_test test_netalyzr netalyzr "./manipulation_tests/netalyzr"

SKIP_IP_VERIFY=1  # Skip IP check for tunnel failure :-)
run_test test_tun_fail tunnel_failure "./leakage_tests/tunnel_failure/"

################################################################################

echo ENDTIME:$(date -u -R) >> $RESULTS_DIR/info

log_checkpoint "pre_disconnect" &  # Background to stop hanging as net recovers

alert "DISCONNECT FROM THE VPN"
pause "Disconnected?"
while [[ "$EXTERNAL_VPN_IP" == $(get_external_ip 3) ]]; do
    warning "Your IP is still the same as on the VPN."
    confirm "Continue anyway?" && break
done

log_checkpoint "pre_transfer" &

info "Transferring results"

transfer_file $TAG $RESULTS_DIR || {
    error "Couldn't transfer results. Connection down?"
    info "Restore your connection, then run:"
    info "    sudo ./run_tests.sh JUST_TRANSFER $TAG $RESULTS_DIR"
    info "to recover..."
}

log_checkpoint "done"

alert "TESTS COMPLETED."

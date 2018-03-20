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

rm -rf $ROOT/*_results/
source $ROOT/venv/bin/activate

# Functions for uploading results and retrieving API keys.
source $ROOT/includes/transfer_func.sh
# Additional helper functions for cleanly running tests.
source $ROOT/includes/helper_funcs.sh

DEFAULT_DIR=`pwd`
DEFAULT_DIR=$DEFAULT_DIR"/"

# collect information about the vpn service
read -p "Enter the name of the VPN service being tested: " VPN_NAME
read -p "Enter the country for the server you are connecting to: " VPN_COUNTRY
read -p "Enter the city you are connectiong to (leave blank if unavailable): " VPN_CITY
read -p "Enter a SHORT + UNIQUE descriptor for the supposed VPN current location (e.g.  'sfo1') : " VPN_LOC_TAG

# create a tag for labeling purposes
PATH_SAFE_VPN_NAME=$(echo "${VPN_NAME// /_}" | clean_str)
PATH_SAFE_VPN_LOC_TAG=$(echo "${VPN_LOC_TAG// /_}" | clean_str)
TAG=${PATH_SAFE_VPN_NAME}_${PATH_SAFE_VPN_LOC_TAG}

#########################################################################################

# create respective directories for results
RESULTS_DIR=$DEFAULT_DIR$TAG"_results/"
mkdir -p $RESULTS_DIR

CONFIG_DIR=$RESULTS_DIR"configs/"
mkdir -p $CONFIG_DIR

TRACES_DIR=$RESULTS_DIR"network_traces/"
mkdir -p $TRACES_DIR

DNS_LEAK_DIR=$RESULTS_DIR"dns_leak/"
mkdir -p $DNS_LEAK_DIR

RTC_LEAK_DIR=$RESULTS_DIR"rtc_leak/"
mkdir -p $RTC_LEAK_DIR

DNS_MANIP_DIR=$RESULTS_DIR"dns_manipulation/"
mkdir -p $DNS_MANIP_DIR

NETALYZR_DIR=$RESULTS_DIR"netalyzr/"
mkdir -p $NETALYZR_DIR

DOM_COLLECTION_DIR=$RESULTS_DIR"dom_collection/"
mkdir -p $DOM_COLLECTION_DIR

REDIR_TEST_DIR=$RESULTS_DIR"redirection/"
mkdir -p $REDIR_TEST_DIR

#########################################################################################

# write the basic info to a file
echo NAME:$VPN_NAME >> $RESULTS_DIR$TAG"_info"
echo COUNTRY:$VPN_COUNTRY >> $RESULTS_DIR$TAG"_info"
echo CITY:$VPN_CITY >> $RESULTS_DIR$TAG"_info"
echo LOC_TAG:$VPN_LOC_TAG >> $RESULTS_DIR$TAG"_info"

# save the default ifconfig and dns nsconfig file
ifconfig -v > $CONFIG_DIR$TAG"_ifconfig_default"
cat /etc/resolv.conf > $CONFIG_DIR$TAG"_resolv_default"

# prompt suer to connect to the VPN service
printf "\n************************************************************************\n"
read -p "CONNET TO THE VPN SERVICE, WHEN THE CONNECTION IS ESTABLISHED, HIT RETURN..."
printf "************************************************************************\n"
read -p "ARE YOU SURE THE VPN CONNECTION ESTSABLISHED? [Y/N]: "
printf "************************************************************************\n"


# run tcp dump instance which collects the complete trace of VPN service
DUMP_FILE=_dump_complete.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export COMPLETE_DUMP_PID=$!

# save  ifconfig and dns config files after the VPN has been connected
#
# XXX: Note from Joe: Just FYI, infrastructure_inference has already been
#      recording this.
ifconfig -v > $CONFIG_DIR$TAG"_ifconfig_connected"
cat /etc/resolv.conf > $CONFIG_DIR$TAG"_resolv_connected"


echo "################--EXECUTING LEAKAGE TESTS--############################"

##############################################################################
#############                 01. DNS LEAK TEST                    ###########
##############################################################################

# Run the test specific capture
DUMP_FILE=_dns_leak.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export DNS_LEAKAGE_PID=$!
echo "-------------------------------------------------------------------------"
echo "01. DNS LEAKAGE TEST"
echo "-------------------------------------------------------------------------"

cd ./leakage_tests/dns/
python3 dns_leak_test.py $DNS_LEAK_DIR | tee $DNS_LEAK_DIR"dns_leak_log"

cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $DNS_LEAKAGE_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "DNS LEAKAGE TEST COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################

##############################################################################
#############                 02. WEBRTC LEAK TEST                 ###########
##############################################################################
# Run the test specific capture
DUMP_FILE=_rtc_leak.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export RTC_LEAKAGE_PID=$!
echo "-------------------------------------------------------------------------"
echo "02. WEB RTC LEAK TEST"
echo "-------------------------------------------------------------------------"

# set up http server

cd ./leakage_tests/webrtc/
python3 -m http.server 8080 & export HTTP_SERVER_PID=$!

python3 webrtc_leak.py $RTC_LEAK_DIR | tee $RTC_LEAK_DIR"rtc_leak_log"

cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $RTC_LEAKAGE_PID
kill -s TERM $HTTP_SERVER_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "WEBRTC TEST COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################


echo "################--EXECUTING MANIPULATION TESTS--############################"


##############################################################################
#############         05. DNS MANIPULATION TEST                    ###########
##############################################################################

# Run the test specific capture
DUMP_FILE=_dns_manipulation.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export DNS_MANIP_PID=$!
echo "-------------------------------------------------------------------------"
echo "03. DNS MANIPULATION TEST"
echo "-------------------------------------------------------------------------"

cd ./manipulation_tests/dns/

./checkdns.sh > $DNS_MANIP_DIR"dns_manipulation_log"

cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $DNS_MANIP_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "DNS MANIPULATION TEST COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################


##############################################################################
#############              06. NETALYZER TEST                   ##############
##############################################################################

# Run the test specific capture
DUMP_FILE=_netalyzr.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export NETALYZR_PID=$!
echo "-------------------------------------------------------------------------"
echo "04. RUNNING NETALYZR"
echo "-------------------------------------------------------------------------"

cd ./manipulation_tests/netalyzr/
python3 run_netalyzr.py $NETALYZR_DIR
cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $NETALYZR_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "NETALYZR TEST COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################


##############################################################################
##############      DOM COLLECTION FOR JS INTERCEPTION        ################
##############################################################################

# Run the test specific capture
DUMP_FILE=_dom_collection.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export DOM_COLL_PID=$!
echo "-------------------------------------------------------------------------"
echo "05. RUNNING DOM COLLECTION FOR JS"
echo "-------------------------------------------------------------------------"

cd ./manipulation_tests/dom_collection/
python3 dom_collection_js.py $DOM_COLLECTION_DIR | tee $DOM_COLLECTION_DIR"dom_collection_log"
cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $DOM_COLL_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "DOM COLLECTION FOR JS COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################


##############################################################################
#########      NETWORK REQUESTS COLLECTION AND REDIRECTS      ################
##############################################################################

# Run the test specific capture
DUMP_FILE=_redir_collection.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export REDIR_COLL_PID=$!
echo "-------------------------------------------------------------------------"
echo "06. RUNNING REDIRECTION TESTS"
echo "-------------------------------------------------------------------------"

cd ./manipulation_tests/redirection/
python3 get_redirects.py $REDIR_TEST_DIR | tee $REDIR_TEST_DIR"redirection_log"
cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $REDIR_COLL_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "REDIRECTION TESTS COMPLETE"
echo "-------------------------------------------------------------------------"

##############################################################################
###################       CONCISE TESTS COLLECTION       #####################
##############################################################################

# First, define how to run each of our tests

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
run_test test_backconnect backconnect "BACKCONNECT"
run_test test_infra_infer infrastructure_inference "INFRASTRUCTURE INFERENCE"
run_test test_ipv6_leakage ipv6_leakage "IPv6 LEAKAGE"
run_test test_tunnel_failure tunnel_failure "TUNNEL FAILURE"
run_test test_recursive_dns_origin recursive_dns_origin "RECURSIVE DNS"


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

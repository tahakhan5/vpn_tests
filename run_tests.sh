#!/bin/bash
rm -rf *_results/
source ./venv/bin/activate

DEFAULT_DIR=`pwd`
DEFAULT_DIR=$DEFAULT_DIR"/"


# collect information about the vpn service
read -p "Enter the name of the VPN service being tested: " VPN_NAME
read -p "Enter the country for the server you are connecting to: " VPN_COUNTRY
read -p "Enter the city you are connectiong to (leave blank if unavailable): " VPN_CITY

# create a tag for labeling purposes
TAG=$(echo "$VPN_NAME" | tr '[:upper:]' '[:lower:]'| sed -e "s/ /_/g")

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

TUNNEL_FAILURE_DIR=$RESULTS_DIR"tunnel_failure/"
mkdir -p $TUNNEL_FAILURE_DIR

V6LEAK_DIR=$RESULTS_DIR"ipv6_leak/"
mkdir -p $V6LEAK_DIR

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
echo $VPN_NAME > $RESULTS_DIR$TAG"_info"
echo $VPN_COUNTRY >> $RESULTS_DIR$TAG"_info"
echo $VPN_CITY >> $RESULTS_DIR$TAG"_info"

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
python dns_leak_test.py $DNS_LEAK_DIR | tee $DNS_LEAK_DIR"dns_leak_log"

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
python -m http.server 8080 & export HTTP_SERVER_PID=$!

python webrtc_leak.py $RTC_LEAK_DIR | tee $RTC_LEAK_DIR"rtc_leak_log"

cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $RTC_LEAKAGE_PID
kill -s TERM $HTTP_SERVER_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "WEBRTC TEST COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################


##############################################################################
#############                 03. TUNNEL FAILURE TEST              ###########
##############################################################################
# Run the test specific capture
DUMP_FILE=_tunnel_failuare.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export TUNNEL_LEAKAGE_PID=$!
echo "-------------------------------------------------------------------------"
echo "02. WEB RTC LEAK TEST"
echo "-------------------------------------------------------------------------"

cd ./leakage_tests/tunnel_failure/
python run_test.py -v -o $TUNNEL_FAILURE_DIR"tunnel_failure_log"

cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $TUNNEL_LEAKAGE_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "TUNNEL FAILURE TEST COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################


##############################################################################
#############                 04. IPv6 LEAK TEST                ##############
##############################################################################


# Run the test specific capture
DUMP_FILE=_ipv6_leak.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export IP_LEAKAGE_PID=$!
echo "-------------------------------------------------------------------------"
echo "02. IPV6 LEAK TEST"
echo "-------------------------------------------------------------------------"

cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $IP_LEAKAGE_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "IPV6 LEAK TEST COMPLETE"
echo "-------------------------------------------------------------------------"


echo "################--EXECUTING MANIPULATION TESTS--############################"


##############################################################################
#############         05. DNS MANIPULATION TEST                    ########### 
##############################################################################

# Run the test specific capture
DUMP_FILE=_dns_manipulation.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export DNS_MANIP_PID=$!
echo "-------------------------------------------------------------------------"
echo "01. DNS MANIPULATION TEST"
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
echo "06. RUNNING NETALYZR"
echo "-------------------------------------------------------------------------"

cd ./manipulation_tests/netalyzr/
python run_netalyzr.py $NETALYZR_DIR
cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $NETALYZR_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "NETALYZR TEST COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################


##############################################################################
############      07. DOM COLLECTION FOR JS INTERCEPTION        ############## 
##############################################################################

# Run the test specific capture
DUMP_FILE=_dom_collection.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export DOM_COLL_PID=$!
echo "-------------------------------------------------------------------------"
echo "07. RUNNING DOM COLLECTION FOR JS"
echo "-------------------------------------------------------------------------"

cd ./manipulation_tests/dom_collection/
python dom_collection_js.py $DOM_COLLECTION_DIR | tee $DOM_COLLECTION_DIR"dom_collection_log"
cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $DOM_COLL_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "DOM COLLECTION FOR JS COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################


##############################################################################
#######      08. NETWORK REQUESTS COLLECTION AND REDIRECTS      ############## 
##############################################################################

# Run the test specific capture
DUMP_FILE=_redir_collection.pcap
tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE & export REDIR_COLL_PID=$!
echo "-------------------------------------------------------------------------"
echo "07. RUNNING REDIRECTION TESTS"
echo "-------------------------------------------------------------------------"

cd ./manipulation_tests/redirection/
python get_redirects.py $REDIR_TEST_DIR | tee $REDIR_TEST_DIR"redirection_log"
cd $DEFAULT_DIR

# Kill the test specific capture
kill -s TERM $REDIR_COLL_PID
sleep 0.5
echo "-------------------------------------------------------------------------"
echo "REDIRECTION TESTS COMPLETE"
echo "-------------------------------------------------------------------------"
################################################################################

echo "************************************************************************"
echo "TESTS COMPLETED."
echo "************************************************************************"

# Kill the process which is collecting the complete dump
#kill -9 $COMPLETE_DUMP_PID
kill -s TERM $COMPLETE_DUMP_PID

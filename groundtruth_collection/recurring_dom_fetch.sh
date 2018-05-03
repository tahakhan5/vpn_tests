#!/bin/bash

usage() {
    if [[ "$@" ]]; then
        echo -e "ERROR: $@\n" >&2
    fi

    cat - <<EOF >&2
This script should run periodically to do DOM collection from a NON-VPN'd host.
EOF
    exit 1
}

NUM_ARGS=1

if [[ "$#" -ne $NUM_ARGS ]]; then
    usage "Invalid Arguments"
fi

[[ "$1" == "GO" ]] || usage "Invalid Arguments"

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

DEFAULT_DIR=`pwd`

# collect information about the vpn service
VPN_NAME=GROUNDTRUTH_DOM_$(date -u '+%y%m%d_%H%M%S')
TAG=$VPN_NAME

# fetch the git commit info
COMMIT=$(cd $ROOT; git rev-parse --verify HEAD)

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
echo COMMIT:$COMMIT >> $RESULTS_DIR$TAG"_info"
echo STARTTIME:$(date -u -R) >> $RESULTS_DIR$TAG"_info"

ifconfig -v > $CONFIG_DIR/$TAG"_ifconfig_default"
cat /etc/resolv.conf > $CONFIG_DIR/$TAG"_resolv_default"
EXTERNAL_VPN_IP=$(get_external_ip)
echo $EXTERNAL_VPN_IP > $CONFIG_DIR/$TAG"_external_ip"

##############################################################################

run_test test_dom_redirection dom_redirection $ROOT/manipulation_tests/redirection_dom/
run_test test_ssl_collection ssl_collection $ROOT/manipulation_tests/ssl/

echo ENDTIME:$(date -u -R) >> $RESULTS_DIR$TAG"_info"

info "Test complete. Transferring results"

transfer_file $TAG $RESULTS_DIR
rm -r $RESULTS_DIR
alert "TRANSER COMPLETE"

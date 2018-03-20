#!/bin/bash

# Runs given test function while recording pcaps and giving updates to the user
run_test() {
    test_func=$1    # Function to call to do the actual test
    test_tag=$2     # Friendly name/tag for this *test*
    test_desc=$3    # A name/description of this test for humans

    test_dir=$RESULTS_DIR$test_tag
    mkdir -p $test_dir

    # Run the test specific capture
    DUMP_FILE=_${test_tag}.pcap
    tcpdump -U -i en0 -s 65535 -w $TRACES_DIR$TAG$DUMP_FILE &
    export REDIR_COLL_PID=$!
    echo "-------------------------------------------------------------------------"
    echo "RUNNING $test_desc TESTS"
    echo "-------------------------------------------------------------------------"

    # Actually run the test
    $test_func $test_dir

    # Kill the test specific capture
    kill -s TERM $REDIR_COLL_PID
    wait $REDIR_COLL_PID
    echo "-------------------------------------------------------------------------"
    echo "TEST $test_desc COMPLETE"
    echo "-------------------------------------------------------------------------"
}

# Blocks until we can access google
wait_until_connected() {
    ping -o -t2 google.com >/dev/null 2>&1
    rv=$?
    while [[ "$rv" -ne 0 ]]; do
        echo -n '.'
        sleep 1
        ping -o -t2 google.com >/dev/null 2>&1
        rv=$?
    done
}

error_exit() {
    echo $@ >&2; exit 1
}

# Helper cleaning function to make names path-safe.
clean_str() {
    tr '[:upper:]' '[:lower:]'| sed -e "s/ /_/g" -e "s/[^a-z_]//g"
}

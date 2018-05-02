#!/bin/bash

# Runs given test function while recording pcaps and giving updates to the user
run_test() {
    test_func=$1    # Function to call to do the actual test
    test_tag=$2     # Friendly name/tag for this *test*
    ch_dir=$3       # Optional directory to change in to before test

    test_dir=$RESULTS_DIR/$test_tag
    mkdir -p $test_dir

    # Run the test specific capture
    DUMP_FILE=${test_tag}.pcap
    tcpdump -U -i en0 -s 65535 -w $TRACES_DIR/$DUMP_FILE &
    export REDIR_COLL_PID=$!
    sleep 1

    info "Running $test_tag tests"

    # Actually run the test
    [[ "$ch_dir" ]] && pushd $ch_dir > /dev/null
    time $test_func $test_dir \
        > >(tee -a $test_dir/std.out) \
        2> >(tee -a $test_dir/std.err >&2)
    [[ "$ch_dir" ]] && popd > /dev/null

    # Kill the test specific capture
    kill -s TERM $REDIR_COLL_PID
    wait $REDIR_COLL_PID
    info "Test $test_tag complete"
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

get_external_ip() {
    curl -sS https://ipv4.projekts.xyz
}

COLOR_NONE=-1
COLOR_BLACK=0
COLOR_RED=1
COLOR_GREEN=2
COLOR_YELLOW=3
COLOR_BLUE=4
COLOR_MAGENTA=5
COLOR_CYAN=6
COLOR_WHITE=7

colorize() {
    tput setaf $1
    shift
    printf "$@\n"
    tput sgr0
}

pause() {
    tput bold
    tput setaf $COLOR_CYAN
    read -s -p "$@ Press any key when ready." -n 1 result
    echo ""
    tput sgr0
}

confirm() {
    tput bold
    tput setaf $COLOR_CYAN
    result=
    while [[ "$result" != 'y' && "$result" != 'n' ]]; do
        read -p "? $@ [y/n]: " result
    done
    tput sgr0
    [[ "$result" == "y" ]] && return 0 || return 1
}

print_bar() {
    char=${1-#}
    width=${2-80}
    bar=$(printf "%-${width}s" " ")
    echo "${bar// /$char}"
}

color_box() {
    color=$1
    char=$2
    shift 2

    tput bold
    [[ "$color" == $COLOR_NONE ]] || tput setaf $color

    print_bar "$char"
    printf "$char %-76s $char\n" "$*"
    print_bar "$char"

    tput sgr0
}

error() {
    color_box $COLOR_RED "#" $*
}

warning() {
    color_box $COLOR_YELLOW "#" $*
}

alert() {
    color_box $COLOR_MAGENTA "#" $*
}

info_box() {
    color_box $COLOR_CYAN "#" $*
}

info() {
    tput bold
    colorize $COLOR_CYAN "# $*"
}

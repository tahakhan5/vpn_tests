#!/bin/bash

LOG_METRICS_SCRIPT=$ROOT/includes/log_metrics

# Runs given test function while recording pcaps and giving updates to the user
run_test() {
    test_func=$1    # Function to call to do the actual test
    test_tag=$2     # Friendly name/tag for this *test*
    ch_dir=$3       # Optional directory to change in to before test

    local pre_ip=$(get_external_ip 2)

    test_dir=$RESULTS_DIR/$test_tag
    mkdir -p $test_dir

    # Run the test specific capture
    DUMP_FILE=${test_tag}.pcap
    tcpdump -U -i en0 -s 65535 -w $TRACES_DIR/$DUMP_FILE 2>/dev/null &
    local TCPDUMP_PID=$!
    sleep 1

    log_checkpoint ${test_tag}_start
    info "Running $test_tag tests"

    # Actually run the test
    [[ "$ch_dir" ]] && pushd $ch_dir > /dev/null
    time $test_func $test_dir \
        > >(tee -a $test_dir/std.out) \
        2> >(tee -a $test_dir/std.err >&2)
    rv=$?
    [[ "$ch_dir" ]] && popd > /dev/null

    # Kill the test specific capture
    kill -s TERM $TCPDUMP_PID
    wait $TCPDUMP_PID

    info "Test $test_tag completed with status $rv"
    log_checkpoint ${test_tag}_done $rv

    [[ "$SKIP_IP_VERIFY" ]] || rerun_if_vpn_failed $pre_ip $test_dir $@
    unset SKIP_IP_VERIFY
}

# Kills the given PID after the given number of seconds
kill_after() {
    pid=$1
    timeout=$2

    n=0
    while kill -0 $pid 2>/dev/null ; do
        ((n+=1))
        sleep 1
        if [[ $n -ge $timeout ]]; then
            echo "Killing pid $pid" >&2
            kill $pid 2>/dev/null
            sleep 1
            kill -0 $pid 2>/dev/null || break
            sleep 2
            kill -0 $pid 2>/dev/null || break
            echo "Kill -9 necessary on $pid" >&2
            kill -9 $pid 2>/dev/null
            sleep 1
            kill -0 $pid 2>/dev/null && echo "Process $pid survived SIGKILL!" >&2
        fi
    done
}

# Blocks until we can access google
wait_until_connected() {
    local max=${1:-0}
    ping -o -t2 google.com >/dev/null 2>&1
    rv=$?
    while [[ "$rv" -ne 0 ]]; do
        echo -n '.'
        sleep 1
        ping -o -t2 google.com >/dev/null 2>&1
        rv=$?

        # Break out
        max=$((max - 1))
        [[ $max -eq 0 ]] && return 1
    done
    return 0
}

error_exit() {
    echo $@ >&2; exit 1
}

# Helper cleaning function to make names path-safe.
clean_str() {
    tr '[:upper:]' '[:lower:]'| sed -e "s/ /_/g" -e "s/[^a-z0-9_]//g"
}

get_external_ip() {
    local tries=${1:-1}
    local ip=$(curl -sS https://ipv4.projekts.xyz)
    while [[ $tries -gt 1 && -z "$ip" ]]; do
        info "Couldn't get IP..."
        sleep 1
        ip=$(curl -sS https://ipv4.projekts.xyz)
        tries=$((tries - 1))
    done
    echo $ip
}

get_external_ip6() {
    curl -sS https://ipv6.projekts.xyz
}

rerun_if_vpn_failed() {
    local pre_ip=$1
    local test_dir=$2
    shift 2

    local ip=$(get_external_ip)

    # If we didn't change IPs, we're good to go.
    [[ "$ip" == "$pre_ip" ]] && return

    if [[ "$MODE" == "AUTO" ]]; then
        error "IP changed during the test from $pre_ip to $ip"
        info "Deleting bad results."
        rm -r $test_dir

        if "$ip" == "$PRE_VPN_IP" ]]; then
            log_checkpoint auto_ip_error_exit "$pre_ip,$ip"
            exit 1
        fi
    fi

    log_checkpoint ip_error "$pre_ip,$ip"

    if [[ "$ip" == "$PRE_VPN_IP" ]] ; then
        error "The VPN has disconnected. Please reconnect to the VPN."
    else
        error "Your IP changed during this test. Please verify VPN connection."
        info "IP was $PRE_VPN_IP and is now $ip."
    fi

    while true; do
        if confirm "VERIFY VPN CONNECTION FIRST. Re-run failed test?"; then
            info "Re-running failed test."
            run_test $@
            return
        elif confirm "Would you like to exit the testing suite?"; then
            if confirm "Delete bad test results?"; then
                rm -r $test_dir
            fi
            info "Exiting, per your request."
            exit 1
        fi
        confirm "*Sigh*. You sure?" && break
    done
}

verify_ipv4_connectivity() {
    local ok=0
    if [[ ! $(get_external_ip) ]] ; then
        error "You do not have valid IPv4 connectivity."
        ok=1
    fi

    return $ok
}

verify_connectivity() {
    local ok=0
    if [[ ! $(get_external_ip) ]] ; then
        error "You do not have valid IPv4 connectivity."
        ok=1
    fi

    if [[ ! $(get_external_ip6) ]] ; then
        error "You do not have valid IPv6 connectivity."
        ok=1
    fi

    return $ok
}

get_commit() {
    echo $(cd $ROOT; git rev-parse --verify HEAD)
}

configure_github_ssh_if_needed() {
    SSH_CONF_DIR=/Users/${SUDO_USER-vpn_test}/.ssh
    grep -sqi '^Host github.com' $SSH_CONF_DIR/config && return

    mkdir -p $SSH_CONF_DIR
    read -r -d '' hostinfo <<EOF
Host github.com
    IdentityFile $ROOT/includes/dropoff_key
EOF
    echo "$hostinfo" >> $SSH_CONF_DIR/config

    info "Installed github keying info."
    info "If it asks a yes/no question, please say yes!:"
}

update_repository() {
    configure_github_ssh_if_needed
    info "Pulling any updates..."
    pushd $ROOT >/dev/null
    sudo -H -u ${SUDO_USER-vpn_test} git pull > /dev/null
    popd >/dev/null
}

log_checkpoint() {
    local extra=
    if [[ "$2" ]]; then
        extra="--extra $2"
    fi

    local t_id=$($LOG_METRICS_SCRIPT checkpoint $TAG $1 $RUN_ID $extra 2> /dev/null)
    if [[ ! "$RUN_ID" ]]; then
        RUN_ID=$t_id
    fi
}


# Installs any system changes if needed
ensure_host_modifications_installed() {
    # Our hostfile needs to shut up Apple's courier service on the vmware hosts
    if ! grep -sqi '^courier.push.apple.com' /etc/hosts ; then
        cat $ROOT/includes/files/courier_hosts >> /etc/hosts
    fi
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
    printf "$@"
    tput sgr0
}

pause() {
    tput bold
    tput setaf $COLOR_MAGENTA
    echo -n "$@ Press any key when ready. "
    while ! read -s -t 1 -n1 result; do
        echo -ne '\a'
    done
    echo ""
    tput sgr0
}

confirm() {
    tput bold
    tput setaf $COLOR_MAGENTA
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

log() {
    [[ "$RESULTS_DIR" ]] || return

    log_file=$RESULTS_DIR/test_log
    local level=$1
    shift 1
    echo $(date '+%F %T'):$level:$@ >> $log_file
}

error() {
    log ERROR $*
    color_box $COLOR_RED "#" $* >&2
}

warning() {
    log WARNING $*
    color_box $COLOR_YELLOW "#" $* >&2
}

alert() {
    log ALERT $*
    color_box $COLOR_MAGENTA "#" $*
}

info_box() {
    log INFO $*
    color_box $COLOR_CYAN "#" $*
}

info() {
    log INFO $*
    tput bold
    colorize $COLOR_CYAN "# $*\n"
}

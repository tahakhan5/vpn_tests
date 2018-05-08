#!/bin/bash

# Figure out the root directory
[[ -z $ROOT ]] && echo "ERROR: Root not defined." && exit 1

_dropoff_ssh() {
    KNOWN_HOST_LINE="vm129.sysnet.ucsd.edu,169.228.66.129 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOctfz281fYE/wab5DwCFa4inP1OtuyLXLjZ8WcGX+2lS/jVWHBa7aJLgx8VLW7SYS9ggteuhhaiU7iAxmRFkGQ="
    known_hosts=$(mktemp)
    echo "$KNOWN_HOST_LINE" > $known_hosts

    ssh \
        -o UserKnownHostsFile=$known_hosts \
        -o IdentitiesOnly=yes \
        -o IdentityFile=$ROOT/includes/dropoff_key \
        -T dropoff@vm129.sysnet.ucsd.edu $@
    rv=$?
    rm $known_hosts
    return $rv
}

transfer_file() {
    tag=$1
    directory=$2
    dir_d=$(dirname $directory)
    dir_b=$(basename $directory)
    tarball=$HOME/.transfer.tar.gz
    tar czf $tarball -C $dir_d $dir_b
    size=$(stat -f "%z" $tarball)
    cat $tarball | _dropoff_ssh upload $tag $size
    rv=$?
    rm $HOME/.transfer.tar.gz
    return $rv
}

fetch_creds() {
    _dropoff_ssh get_creds > $ROOT/infrastructure_inference/creds.json
}

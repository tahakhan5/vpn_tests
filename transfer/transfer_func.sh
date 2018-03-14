#!/bin/bash

transfer_file() {
    tag=$1
    directory=$2

    KNOWN_HOST_LINE="vm129.sysnet.ucsd.edu,169.228.66.129 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOctfz281fYE/wab5DwCFa4inP1OtuyLXLjZ8WcGX+2lS/jVWHBa7aJLgx8VLW7SYS9ggteuhhaiU7iAxmRFkGQ="
    known_hosts=$(mktemp)
    echo "$KNOWN_HOST_LINE" > $known_hosts

    tar czf - $directory \
        | ssh \
            -o UserKnownHostsFile=$known_hosts \
            -o IdentitiesOnly=yes \
            -o IdentityFile=dropoff_key \
            -T \
            dropoff@vm129.sysnet.ucsd.edu $tag
    rv=$?
    rm $known_hosts
    return $rv
}

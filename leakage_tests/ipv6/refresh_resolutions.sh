#!/bin/bash

# Overwrite the v6_resolutions.csv file with updated resolutions for each host.
#
# Run me periodically, I guess.

RESOLUTION_FILE=${1:-v6_resolutions.csv}

tmp=$(mktemp)

while read line; do
    domain=${line/,*}
    results=$(dig +short AAAA $domain | awk -v ORS=', ' '1')
    results=${results%,*}
    echo $domain, $results >> $tmp
    sleep .05
done < <(cat $RESOLUTION_FILE)

mv $tmp $RESOLUTION_FILE

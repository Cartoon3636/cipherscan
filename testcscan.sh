#!/usr/bin/env bash
for t in $(head -n 10 < top1m/top-1m.csv |cut -d ',' -f 2|cut -d "/" -f 1)
do
    tcping -u 10000000 $t 443 > /dev/null 2>/dev/null
    if [[ $? -gt 0 ]]; then
        continue
    fi
    ./cscan.sh $t 443 > /dev/null
    ret=$?
    if [[ $ret -eq 0 ]]; then
        echo -n .
    else
        echo
        if [[ $ret -eq 1 ]]; then
            echo $t is SNI ext incompatible
        elif [[ $ret -eq 2 ]]; then
            echo $t is Xmas-client-hello incompatible
        elif [[ $ret -eq 3 ]]; then
            echo $t appears TLSv1.3 incompatible
        elif [[ $ret -eq 4 ]]; then
            echo $t refused connection
        elif [[ $ret -eq 5 ]]; then
            echo $t inconsistent results
        fi
    fi
done

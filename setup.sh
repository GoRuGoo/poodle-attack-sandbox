#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run by root"
	exit 1
fi


function end(){
	kill $PID1
    iptables -F
	wait $PID1
}

trap 'end' INT

iptables -A INPUT -i lo -p tcp --dport 443 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -o lo -p tcp --dport 443 -j NFQUEUE --queue-num 0

python3 ./sandbox/python-capture-sandbox/capture-test.py 2>&1 &
PID1=$!

cat

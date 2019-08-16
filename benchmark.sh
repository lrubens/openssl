#!/bin/bash

set -e

if [ "$(whoami)" != "root" ]; then
    echo "Please run me as root"
    exit 1;
fi

docker run --rm --detach --interactive --tty --name server --env I_AM_SERVER=server opensslkem 
echo "hello"
LATENCIES="0" # 0.5 1 2 3 4 5 10 15 20 25 30 40 50 60 70 80 90 100 120 140 160 180 200 250 300 350 400"

# figure out interface
#INTERFACE=$(./dockerveth.sh | cut -f2)
INTERFACE=docker0
SERVERIP=$(docker container inspect server | jq -r ".[0].NetworkSettings.IPAddress")
ENC_PARAM=round5_r5n1_1kem_0d
# Output directory
DIR=measurements

quit() {
    echo "Stopping"
    echo "Terminating server container"
    docker kill server
    exit $1
}

mkdir -p "${DIR}"

echo "Name of the server interface: $INTERFACE"
echo "IP address of the server: $SERVERIP"

for lat in $LATENCIES; do
    echo "Setting up measurements for $lat ms"
    #tc qdisc add dev docker0 root netem delay ${lat}ms

    echo "Setting up monitoring"
    tcpdump --time-stamp-precision nano -i $INTERFACE -w ${DIR}/$ENC_PARAM.pcap &
    sleep 3

    echo "Run measurements"
    docker run --rm --interactive --tty --name client --env SERVERIP=$SERVERIP --env ENC_PARAM=$ENC_PARAM opensslkem

    echo "Stopping monitoring"
    killall -INT tcpdump || quit 1
    sleep 3

    echo "Checking if tcpdump quit."
    pgrep tcpdump && quit 1 || true

    echo "Removing latency"
    tc qdisc del dev $INTERFACE root netem delay ${lat}ms
    sleep 2
   # docker container stop server
done

echo "Done!"

quit 0

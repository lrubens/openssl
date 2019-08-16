#!/bin/bash

set -e

if [ "$I_AM_SERVER" = "server" ]; then 
    echo "I am a server"
    ./apps/openssl s_server -cert rsa_CA.crt -key rsa_CA.key -curves $ENC_PARAM -tls1_3
else
    echo "I am a client"
    for i in $(seq 1 20); do
        echo "Attempt $i"
        echo hi | ./apps/openssl s_client -quiet -connect $SERVERIP:4433 -curves $ENC_PARAM -tls1_3
    done
fi

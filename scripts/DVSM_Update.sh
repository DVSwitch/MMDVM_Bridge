#!/usr/bin/env bash
set -o errexit

# N4IRS 01/17/2020

#################################################
#                                               #
#                                               #
#                                               #
#################################################

# Start here
/opt/MMDVM_Bridge/dvswitch.sh update

DIR="/usr/share/ircddbgateway/"
if [ -d "$DIR" ]; then
        rm /usr/share/ircddbgateway/DCS_Hosts.txt
        rm /usr/share/ircddbgateway/DExtra_Hosts.txt
        rm /usr/share/ircddbgateway/DPlus_Hosts.txt

        ln -s /var/lib/mmdvm/DCS_Hosts.txt /usr/share/ircddbgateway/DCS_Hosts.txt
        ln -s /var/lib/mmdvm/DExtra_Hosts.txt /usr/share/ircddbgateway/DExtra_Hosts.txt
        ln -s /var/lib/mmdvm/DPlus_Hosts.txt /usr/share/ircddbgateway/DPlus_Hosts.txt
fi

FILE="/var/lib/mmdvm/private_NXDNHosts.txt"
if [ ! -f "$FILE" ]; then
        touch $FILE
fi

FILE="/var/lib/mmdvm/private_P25Hosts.txt"
if [ ! -f "$FILE" ]; then
        touch $FILE
fi


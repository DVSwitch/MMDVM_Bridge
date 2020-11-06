#!/usr/bin/env bash
set -o errexit

# N4IRS 10/30/2020
# Version 1.6.0

#################################################
#                                               #
# Download updated host files and setup links   #
#                                               #
#################################################

# Use dvswitch.sh to get the host files
/opt/MMDVM_Bridge/dvswitch.sh update

# create symbolic links for ircddbgateway
DIR="/usr/share/ircddbgateway/"
if [ -d "$DIR" ]; then
        rm /usr/share/ircddbgateway/DCS_Hosts.txt
        rm /usr/share/ircddbgateway/DExtra_Hosts.txt
        rm /usr/share/ircddbgateway/DPlus_Hosts.txt

        ln -s /var/lib/mmdvm/DCS_Hosts.txt /usr/share/ircddbgateway/DCS_Hosts.txt
        ln -s /var/lib/mmdvm/DExtra_Hosts.txt /usr/share/ircddbgateway/DExtra_Hosts.txt
        ln -s /var/lib/mmdvm/DPlus_Hosts.txt /usr/share/ircddbgateway/DPlus_Hosts.txt
fi

# if private host file(s) do not exist create empty ones
FILE="/var/lib/mmdvm/private_NXDNHosts.txt"
if [ ! -f "$FILE" ]; then
        touch $FILE
fi

FILE="/var/lib/mmdvm/private_P25Hosts.txt"
if [ ! -f "$FILE" ]; then
        touch $FILE
fi


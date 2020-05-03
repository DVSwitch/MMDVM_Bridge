#!/bin/bash

#################################################################
# /*
#  * Copyright (C) 2019 N4IRR
#  *
#  * Permission to use, copy, modify, and/or distribute this software for any
#  * purpose with or without fee is hereby granted, provided that the above
#  * copyright notice and this permission notice appear in all copies.
#  *
#  * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
#  * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  * AND FITNESS.  IN NO EVENT SHALL N4IRR BE LIABLE FOR ANY SPECIAL, DIRECT,
#  * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
#  * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
#  * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  * PERFORMANCE OF THIS SOFTWARE.
#  */
#################################################################

#DEBUG=echo
#set -xv   # this line will enable debug

SCRIPT_VERSION="dvswitch.sh 1.5.4"

AB_DIR=${AB_DIR:-"/var/lib/dvswitch"}
MMDVM_DIR=${MMDVM_DIR:-"/var/lib/mmdvm"}
DVSWITCH_INI=${DVSWITCH_INI:-"/opt/MMDVM_Bridge/DVSwitch.ini"}
NODE_DIR=${NODE_DIR:-"/tmp"}

# Default server and port assignment, but overridden by value in ABInfo
TLV_PORT=36000
SERVER=127.0.0.1

# HTTP_PORT is used for the simple server that supports data file uploads
HTTP_PORT=9042

# Error codes defined below
SUCCESSS=0
ERROR_FILE_NOT_FOUND=-1
ERROR_INVALID_ARGUMENT=-2
ERROR_EMPTY_FILE=-3
ERROR_DIR_NOT_FOUND=-4
ERROR_INVALID_FILE=-5
_ERRORCODE=$SUCCESSS

#################################################################
# Return value from ABInfo_xxxx.json
# The value may be an value, object/value or object/object/value
#################################################################
function getABInfoValue() {
    declare _json_file=`getABInfoFileName`
python - <<END
#!/usr/bin/env python
try:
    import json, os

    json = json.loads(open("$_json_file").read())
    if "$2" == "":  # Not all values are enclosed in an object
        value = json["$1"]
    else:
        if "$3" == "":
            value = json["$1"]["$2"]
        else:
            value = json["$1"]["$2"]["$3"]
    print(value)
except:
    exit(1)
END
}

#################################################################
# get file name of the current ABInfo json file
#################################################################
function getABInfoFileName() {
        if [ -z "${ABINFO}" ]; then # if no enviornment variable, use the latest file in /tmp
        declare _json_file=`ls -t /tmp/ABInfo_*.json 2>/dev/null | head -1`
    else
        declare _json_file=$ABINFO  # Use the environment variable (probably set by AB)
    fi
    echo $_json_file
}

#################################################################
# Parse and print out an ini file value
# parseIniFile fileName stanza tag
#################################################################
function parseIniFile() {
python - <<END
#!/usr/bin/env python
try:
    import sys, ConfigParser
    config = ConfigParser.ConfigParser()
    config.read("$1")
    print( config.get('$2', '$3') )
except:
    exit(1)
END
}

#################################################################
# Return TLV_PORT from ABInfo_xxxx.json
# This is the port  that AB is listening to for commands and MB 
# packets.
#################################################################
function getTLVPort() {
    getABInfoValue tlv rx_port
}

#################################################################
# Tune to a specific TG/Reflector/Server, etc
# Argument 1 is the TG to tune to.  The argument is mode specific.
#################################################################
function tune() {
    if [ $# -eq 0 ]; then
        getABInfoValue last_tune
    else
        remoteControlCommand "txTg=$1"
    fi
}

#################################################################
# Set the number of bits that AB will use to encode a PCM sample
# The bits in argument 1 (48, 49, 72 or 88) are mode specific
#################################################################
function setAmbeSize() {
    if [ $# -eq 0 ]; then
        getABInfoValue tlv ambe_size
    else
        remoteControlCommand "ambeSize=$1"
    fi
}

#################################################################
# Set the slot to transmit on.  Slot may be 1 or 2
#################################################################
function setSlot() {
    if [ $# -eq 0 ]; then
        getABInfoValue digital ts
    else
        remoteControlCommand "txTs=$1"
    fi
}

#################################################################
# Set the AMBE mode of Analog_Bridge to DMR|DSTAR|NXDN|YSFN|YSFW|P25
#################################################################
function setAmbeMode() {
    if [ $# -eq 0 ]; then
        getABInfoValue tlv ambe_mode
    else
        remoteControlCommand "ambeMode=$1"
    fi
}

#################################################################
# Send graceful exit command to Analog_Bridge
#################################################################
function exitAnalogBridge() {
    remoteControlCommand "exit=$1 $2"
}

#################################################################
# Set the analog audio shaping type
# argument may be AUDIO_UNITY, AUDIO_USE_AGC, AUDIO_USE_GAIN
#################################################################
function setUSRPAudioType() {
    if [ $# -eq 0 ]; then
        getABInfoValue usrp to_pcm shape
    else
        remoteControlCommand "usrpAudio=$1"
    fi
}

#################################################################
# Set the digital audio shaping type
# argument may be AUDIO_UNITY, AUDIO_USE_GAIN, AUDIO_USE_BPF
#################################################################
function setTLVAudioType() {
    if [ $# -eq 0 ]; then
        getABInfoValue usrp to_ambe shape
    else
        remoteControlCommand "tlvAudio=$1"
    fi
}

#################################################################
# Set the analog (PCM) audio gain
#  Argument may be between 0 - x, where
# < 1 will decrease audio level from unity
# 1 = UNITY gain
# > 1 will increase audio level above unity
#################################################################
function setUSRPGain() {
    if [ $# -eq 0 ]; then
        getABInfoValue usrp to_pcm gain
    else
        remoteControlCommand "usrpGain=$1"
    fi
}

#################################################################
# Set the digital audio gain
#################################################################
function setTLVGain() {
    if [ $# -eq 0 ]; then
        getABInfoValue usrp to_ambe gain
    else
        remoteControlCommand "tlvGain=$1"
    fi
}

#################################################################
# Set the USRP agc params to threshold, slope and decay
#################################################################
function setUSRPAgc() {
    if [ $# -eq 0 ]; then
        echo "Argument required: AGC parameters (threshold, slope  and decay)"
        _ERRORCODE=$ERROR_INVALID_ARGUMENT
    else
        remoteControlCommand "agcUSRP=$1,$2,$3"
    fi
}

#################################################################
# Set the TLV agc params to threshold, slope and decay
#################################################################
function setTLVAgc() {
    if [ $# -eq 0 ]; then
        echo "Argument required: AGC parameters (threshold, slope  and decay)"
        _ERRORCODE=$ERROR_INVALID_ARGUMENT
    else
        remoteControlCommand "agcTLV=$1,$2,$3"
    fi
}

#################################################################
# Set the USRP audio codec to {SLIN|ULAW|ADPCM}
#################################################################
function setUSRPCodec() {
    if [ $# -eq 0 ]; then
        echo "Argument required: codec"
        _ERRORCODE=$ERROR_INVALID_ARGUMENT
    else
        string='|SLIN|ULAW|ADPCM|slin|ulaw|adpcm|'
        if [[ $string == *"|$1|"* ]]; then
            remoteControlCommand "codec=$1"
        else
            echo "Invalid argument: {slin|ulaw|adpcm}"
            _ERRORCODE=$ERROR_INVALID_ARGUMENT
        fi
    fi
}

#################################################################
# set the AB listener port
#################################################################
function setTLVRxPort() {
    if [ $# -eq 0 ]; then
        getABInfoValue tlv rx_port
    else
        remoteControlCommand "rxport=$1"
        sleep 1
        TLV_PORT=`getTLVPort`   # We have changed the listener on AB, so we must adjust our sending port
    fi
}

#################################################################
# Set the AB -> MB transmit port
#################################################################
function setTLVTxPort() {
    if [ $# -eq 0 ]; then
        getABInfoValue tlv tx_port
    else
        remoteControlCommand "txport=$1"
    fi
}

#################################################################
# Send the info packet to a USRP client (DVSM/UC)
#################################################################
function getInfo() {
    if [ $# -eq 0 ]; then
        remoteControlCommand "info"
    else
        getABInfoValue $1 $2
    fi
}

#################################################################
# mute AB ("OFF", "USRP", "TLV", "BOTH")
#################################################################
function setMute() {
    if [ $# -eq 0 ]; then
        getABInfoValue mute
    else
        remoteControlCommand "mute=$1"
    fi
}

#################################################################
# Send "text" message to Mobile
#################################################################
function sendMessage() {
    if [ -z "$1" ]; then
        echo "Argument required: text"
        _ERRORCODE=$ERROR_INVALID_ARGUMENT
    else
        remoteControlCommand "message=$1"
    fi
}

#################################################################
# Send a macro definition or file to Mobile
#################################################################
function sendMacro() {
    if [ -z "$2" ]; then
        echo "Argument required: file or text"
        _ERRORCODE=$ERROR_INVALID_ARGUMENT
    else
        remoteControlCommand "$1=$2"
    fi
}

#################################################################
# Set the ping timer (keep alive)
#################################################################
function setPingTimer() {
    if [ -z "$1" ]; then
        getABInfoValue usrp ping
    else
        remoteControlCommand "ping=$1"
    fi
}

#################################################################
# Tell AB to reload database files from disk into memory
#################################################################
function reloadDatabase() {
    remoteControlCommand "reloadDatabase"
}

#################################################################
# Send the remote control TLV command to Analog_Bridge
#################################################################
function remoteControlCommand() {
    if [ ! -z "${DEBUG}" ]; then
        echo "remoteControlCommand $1"
    else
python - <<END
#!/usr/bin/env python
try:
    import sys, socket, struct
    cmd = "$1".encode("utf-8")
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd = struct.pack("BB", 0x05, len(cmd))[0:2] + cmd
    _sock.sendto(cmd, ('$SERVER', $TLV_PORT))
    _sock.close()
except:
    exit(1)
END
    fi
}

#################################################################
# Compose a USRP packet and send it to AB (WIP: address and port)
#################################################################
function USRPCommand() {
python - <<END
#!/usr/bin/env python
import traceback, struct, socket
try:
    usrpSeq = 1
    packetType = $1
    cmd = "$2"
    usrp = 'USRP'.encode('ASCII') + (struct.pack('>iiiiiii',usrpSeq, 0, 0, 0, packetType << 24, 0, 0)) + cmd
    usrpSeq = (usrpSeq + 1) & 0xffff
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.sendto(usrp, ("127.0.0.1", 12345))
    udp.close()
except:
    traceback.print_exc()
END
}

#################################################################
# 
#################################################################
function setCallAndID() {
    if [ ! -z "${DEBUG}" ]; then
        echo "setCallAndID $1"
    else
python - <<END
#!/usr/bin/env python
try:
    import sys, socket, struct

    call = "$1"
    dmr_id = $2
    tlvLen = 3 + 4 + 3 + 1 + 1 + len(call) + 1                      # dmrID, repeaterID, tg, ts, cc, call, 0
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd = struct.pack("BBBBBBBBBBBBBB", 0x08, tlvLen, ((dmr_id >> 16) & 0xff),((dmr_id >> 8) & 0xff),(dmr_id & 0xff),0,0,0,0,0,0,0,0,0)[0:14] + call + chr(0)
    _sock.sendto(cmd, ('$SERVER', $TLV_PORT))
    _sock.close()
except:
    exit(1)
END
    fi
}

#################################################################
# Tell AB to upload a file to the Mobile client
#################################################################
function pushFileToClient() {
    if [ ! -z "${DEBUG}" ]; then
        echo "remoteControlCommand pushFileToClient $1"
    else
        if [ ! -f $1 ]; then
            echo "File $1 does not exist, abort transfer"
            return
        fi
        size=`wc -c $1 | awk '{print $1}'`
        if (($size == 0)); then
            echo "file is empty, abort transfer"
            return
        fi

python - <<END
#!/usr/bin/env python
try:
    import sys, socket, struct

    TLV_TAG_FILE_XFER  = 11
    FILE_SUBCOMMAND_READ = 3
    name = "$1".encode("utf-8")
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd = struct.pack("BBB", TLV_TAG_FILE_XFER, len(name)+2, FILE_SUBCOMMAND_READ)[0:3] + name + chr(0)
    _sock.sendto(cmd, ('$SERVER', $TLV_PORT))
    _sock.close()
except:
    exit(1)
END
    fi
}

#################################################################
# Push a local file as a URL to DVSM.  The file is checked for
# whether it exists and has a size > 0 bytes. Arguments are
# Directory, Server IP and file name.
#################################################################
function pushLocalFileAsURLToClient() {

    if [ ! -f "$1/$3" ]; then
        echo "File $1/$3 does not exist, abort transfer"
        _ERRORCODE=$ERROR_FILE_NOT_FOUND
        return
    fi
    declare size=`wc -c "$1/$3" | awk '{print $1}'`
    if (($size == 0)); then
        echo "file is empty, abort transfer"
        _ERRORCODE=$ERROR_EMPTY_FILE
        return
    fi
    pushURLToClient "$2/$3"
}

#################################################################
# Send the URL of a file to download to DVSM.  DVSM knows that if
# the name begins with http it is a URL.
#################################################################
function pushURLToClient() {
python - <<END
#!/usr/bin/env python
try:
    import sys, socket, struct

    TLV_TAG_FILE_XFER  = 11
    FILE_SUBCOMMAND_READ = 3
    name = "$1".encode("utf-8")
    _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd = struct.pack("BBB", TLV_TAG_FILE_XFER, len(name)+2, FILE_SUBCOMMAND_READ)[0:3] + name + chr(0)
    _sock.sendto(cmd, ('$SERVER', $TLV_PORT))
    _sock.close()
except:
    exit(1)
END
}

#################################################################
# Parse Pi-Star YSF reflector file
#################################################################

function ParseYSFile() {
    curl --fail -o "$NODE_DIR/$1" -s http://www.pistar.uk/downloads/$1
python - <<END
try:
    print("disconnect|||Unlink") # Make sure unlink is first in list
    f=open("$NODE_DIR/$1", "r")
    if f.mode == 'r':
        lines = f.readlines()
        for line in lines:
            line = line.replace('\r', '')
            line = line.replace('\n', '')
            if line[0:1] == '#':
                pass
            else:
                fields = line.split(';')
                print(fields[3] + ":" + fields[4] + "|||" + fields[1])
        f.close()
except:
    exit(1)
END
}

#################################################################
# Parse Pi-Star talk group files
#################################################################
function ParseTGFile() {
    curl --fail -o "$NODE_DIR/$1" -s http://www.pistar.uk/downloads/$1
python - <<END
try:
    print("4000|||Unlink") # Make sure unlink is first in list
    f=open("$NODE_DIR/$1", "r")
    if f.mode == 'r':
        lines = f.readlines()
        for line in lines:
            line = line.replace('\r', '')
            line = line.replace('\n', '')
            if line[0:1] == '#':
                pass
            else:
                fields = line.split(';')
                print(fields[0] + "|||" + fields[2].split('_TG')[0].replace('_',' '))
        f.close()
except:
    exit(1)
END
}

#################################################################
# Create a default DSTAR database.  I know this is probably not
# what you want, but I feel that a full list of all DSTAR nodes
# with all modules included would not be very useful.  So, just
# add your own favorites here (like I did).
#################################################################
function ParseDStarFile() {
    echo "       U|||Unlink"
    echo "REF001EL|||Echo"
    echo "       I|||Info"
    echo "REF001CL|||REF001 C"
    echo "REF004CL|||REF004 C"
    echo "REF012AL|||REF012 A"
    echo "XRF012AL|||XRF012 A"
    echo "REF014CL|||REF014 C"
    echo "REF030BL|||REF030 B"
    echo "REF030CL|||REF030 C"
    echo "REF038CL|||REF038 C"
    echo "REF050CL|||REF050 C"
    echo "REF058BL|||REF058 B"
    echo "REF078BL|||REF078 B"
    echo "REF078CL|||REF078 C"
    echo "DCS006FL|||DCS006 F"
    echo "DCS059AL|||DCS059 A"
}

#################################################################
# A general function to parse MMDVM host files
#################################################################
function ParseNodeFile() {
    curl --fail -o "$NODE_DIR/$1" -s http://www.pistar.uk/downloads/$1
python - <<END
try:
    print("9999|||Unlink") # Make sure unlink is first in list
    f=open("$NODE_DIR/$1", "r")
    if f.mode == 'r':
        lines = f.readlines()
        state = 0
        for line in lines:
            line = line.replace('\r', '')
            line = line.replace('\n', '')
            if state == 0:
                if len(line) == 0:
                    state = 1
            elif state == 1:
                comment = line[2:]
                state = 2
            elif state == 2:
                node = line.split()[0]
                print(node + "|||" + comment)
                state = 0
        f.close()
except:
    exit(1)
END
}

#################################################################
# Get the current ASL node list (used by allmon) and do a simple
# validation (look for my node number)
#################################################################
function DownloadAndValidateASLNodeList() {
    curl --fail -o "$NODE_DIR/$1" -s https://allstarlink.org/cgi-bin/allmondb.pl
    declare isValid=`grep -i N4IRS "$NODE_DIR/$1"`
    if [ -z "${isValid}" ]; then
        rm "$NODE_DIR/$1"
        echo "ASL node list is not valid, ignoring"
    fi
}

#################################################################
# 
#################################################################
function collectProcessDataFiles() {

    echo "Processing NXDN"
    ParseNodeFile NXDN_Hosts.txt > $NODE_DIR/NXDN_node_list.txt 2>/dev/null

    echo "Processing P25"
    ParseNodeFile P25_Hosts.txt > $NODE_DIR/P25_node_list.txt 2>/dev/null

    echo "Processing DMR"
    ParseTGFile TGList_BM.txt > $NODE_DIR/DMR_node_list.txt 2>/dev/null

    echo "Processing YSF"
    ParseYSFile YSF_Hosts.txt > $NODE_DIR/YSF_node_list.txt 2>/dev/null

    echo "Processing DStar"
    ParseDStarFile DSTAR_Hosts.txt > $NODE_DIR/DSTAR_node_list.txt 2>/dev/null

    echo "Processing ASL"
    DownloadAndValidateASLNodeList node_list.txt 2>/dev/null
}

#################################################################
# Get all mobile data files, proces them into proper format and 
# push them to the device
#################################################################
function collectProcessPushDataFiles() {

    collectProcessDataFiles

    echo "Pushing NXDN"
    pushFileToClient "$NODE_DIR/NXDN_node_list.txt"

    echo "Pushing P25"
    pushFileToClient "$NODE_DIR/P25_node_list.txt"

    echo "Pushing DMR"
    pushFileToClient "$NODE_DIR/DMR_node_list.txt"

    echo "Pushing YSF"
    pushFileToClient "$NODE_DIR/YSF_node_list.txt"

    echo "Pushing DStar"
    pushFileToClient "$NODE_DIR/DSTAR_node_list.txt"

    echo "Pushing ASL"
    pushFileToClient "$NODE_DIR/node_list.txt"
}

#################################################################
# Utility function to get  the primary IP address
#################################################################
function getMyIP() {
    declare _ip _line
    while IFS=$': \t' read -a _line ;do
        [ -z "${_line%inet}" ] &&
           _ip=${_line[${#_line[1]}>4?1:2]} &&
           [ "${_ip#127.0.0.1}" ] && echo $_ip && return 0
      done< <(LANG=C /sbin/ifconfig)
}

#################################################################
# Get all mobile data files, proces them into proper format and 
# push the URL to the device.  Starts a simple web server on port
# $HTTP_PORT (9042).
#################################################################
function collectProcessPushDataFilesHTTP() {

    declare processID=`ps aux | grep "python -m SimpleHTTPServer $HTTP_PORT" | grep -v grep | awk '{print $2}'`
    kill $processID 2>/dev/null
    pushd "$NODE_DIR"
    python -m SimpleHTTPServer $HTTP_PORT &
    popd
    declare _MYIP=`getMyIP`
    PSERVER="http://${_MYIP}:$HTTP_PORT"

    collectProcessDataFiles

    echo "Pushing NXDN"
    pushLocalFileAsURLToClient "$NODE_DIR" "$PSERVER" "NXDN_node_list.txt"
    sleep 5

    echo "Pushing P25"
    pushLocalFileAsURLToClient "$NODE_DIR" "$PSERVER" "P25_node_list.txt"
    sleep 5

    echo "Pushing DMR"
    pushLocalFileAsURLToClient "$NODE_DIR" "$PSERVER" "DMR_node_list.txt"
    sleep 5

    echo "Pushing YSF"
    pushLocalFileAsURLToClient "$NODE_DIR" "$PSERVER" "YSF_node_list.txt"
    sleep 5

    echo "Pushing DStar"
    pushLocalFileAsURLToClient "$NODE_DIR" "$PSERVER" "DSTAR_node_list.txt"
    sleep 5

    echo "Pushing ASL"
    pushLocalFileAsURLToClient "$NODE_DIR" "$PSERVER" "node_list.txt"
    sleep 10

    processID=`ps aux | grep "python -m SimpleHTTPServer $HTTP_PORT" | grep -v grep | awk '{print $2}'`
    kill $processID 2>/dev/null

    sendMessage "Database update complete"

}

#################################################################
# Download and validate a file.  This function will use curl to download
# a file from a server and test for valid data.  The tests include
# a warning on download failure, and errors for file size and valid contents. 
#################################################################
function downloadAndValidate() {
    ${DEBUG} curl --fail -o "$MMDVM_DIR/$1" -s "http://www.pistar.uk/downloads/$2"
    if (( $? != 0 )); then
        echo "Warning, download failure"
        _ERRORCODE=$ERROR_FILE_NOT_FOUND
    fi
    if [ ! -f $MMDVM_DIR/$1 ]; then
        echo "Error, $1 file does not seem to exist"
        _ERRORCODE=$ERROR_INVALID_FILE
    else
        declare _fileSize=`wc -c $MMDVM_DIR/$1 | awk '{print $1}'`
        if (( ${_fileSize} < 10 )); then
            echo "Error, $1 file has no contents"
            _ERRORCODE=$ERROR_INVALID_FILE
        else
            declare isValid=`grep $3 "$MMDVM_DIR/$1"`
            if [ -z "$isValid" ]; then
                echo "Error, $1 file does not seem to be valid"
                _ERRORCODE=$ERROR_INVALID_FILE
            fi
        fi
    fi
}

#################################################################
# Download all user databases
#################################################################
function downloadDatabases() {
    if [ -d "${MMDVM_DIR}" ] && [ -d "${AB_DIR}" ]; then

        ${DEBUG} curl -s -N "https://www.radioid.net/static/user.csv" | awk -F, 'NR>1 {if ($1 > "") print $1,$2,$3}' > "${MMDVM_DIR}/DMRIds.dat"
        ${DEBUG} curl -s -N "https://www.radioid.net/static/user.csv" | awk -F, 'BEGIN{OFS=",";} NR>1 {if ($1 > "") print $1,$2,$3}' > "${AB_DIR}/subscriber_ids.csv"
        ${DEBUG} curl -s -N "https://www.radioid.net/static/nxdn.csv" > "${MMDVM_DIR}/NXDN.csv"

        downloadAndValidate "NXDNHosts.txt" "NXDN_Hosts.txt" "dvswitch.org"
        downloadAndValidate "P25Hosts.txt" "P25_Hosts.txt" "dvswitch.org"
        downloadAndValidate "TGList_BM.txt" "TGList_BM.txt" "DVSWITCH"
        downloadAndValidate "YSFHosts.txt" "YSF_Hosts.txt" "dvswitch.org"

        downloadAndValidate "FCSRooms.txt" "FCS_Hosts.txt" "FCS00106"
        downloadAndValidate "DCS_Hosts.txt" "DCS_Hosts.txt" "DCS006"
        downloadAndValidate "DPlus_Hosts.txt" "DPlus_Hosts.txt" "REF030"
        downloadAndValidate "DExtra_Hosts.txt" "DExtra_Hosts.txt" "XRF012"
        downloadAndValidate "XLXHosts.txt" "XLXHosts.txt" "000"
        downloadAndValidate "APRS_Hosts.txt" "APRS_Hosts.txt" "central.aprs2.net"

        declare isValid=`grep 3113043 "${MMDVM_DIR}/DMRIds.dat"`
        if [ -z "$isValid" ]; then
            echo "Error, DMR ID file does not seem to be valid"
            _ERRORCODE=$ERROR_INVALID_FILE
        fi
    else
        echo "Destination directory does not exist, aborting"
        _ERRORCODE=$ERROR_DIR_NOT_FOUND
    fi
}

#################################################################
# Set digital mode of AB/MB getting the proper ports from DVSwitch.ini
#################################################################
function setMode() {
    if [ $# -eq 0 ]; then   # No argument passed, just return the current value
        echo `getABInfoValue tlv ambe_mode`
    else
        declare _MODE=`echo $1 | tr '[:lower:]' '[:upper:]'`
        if [[ "DMRYSFP25NXDNDSTAR" == *"$_MODE"* ]]; then
            ${DEBUG} setTLVRxPort 30000  # cause AB to stop listening
            _MBTX=`parseIniFile "$DVSWITCH_INI" "$_MODE" "TXPort"`
            _MBRX=`parseIniFile "$DVSWITCH_INI" "$_MODE" "RXPort"`
            if [ ! -z $_MBTX ]; then
                sendMessage "Setting mode to $_MODE"
                ${DEBUG} setAmbeMode $_MODE
                ${DEBUG} setTLVTxPort ${_MBRX}
                ${DEBUG} setTLVRxPort ${_MBTX}
                ${DEBUG} getInfo
            else
                echo "Error, DVSwitch.ini file not found"
                _ERRORCODE=$ERROR_FILE_NOT_FOUND
            fi
        else
            echo "Error, Mode must be DMR or YSF or P25 or DSTAR or NXDN"
            _ERRORCODE=$ERROR_INVALID_ARGUMENT
        fi
    fi
}

#################################################################
# Show pretty ABInfo json file
#################################################################
function prettyPrintInfo() {
    declare _abname=`getABInfoFileName`
    if [ -f ${_abname} ]; then
        python -mjson.tool ${_abname} 
    else
        echo ABInfo file not found
    fi
}

#################################################################
# Lookup info in database file
#################################################################
function lookup() {
    declare databaseName="${MMDVM_DIR}/DMRIds.dat"
    if [ -f "${databaseName}" ]; then
        grep -i $1 "${databaseName}"
    else
        echo DMR ID database file not found at ${databaseName}
    fi
}

#################################################################
# Show usage string to someone who wants to know the available options
#################################################################
function usage() {
    echo -e "Usage:"
    echo -e "$0 \n\t { version | mode | tune | ambesize | ambemode | slot | update | tlvAudio | usrpAudio | usrpCodec | tlvPorts | "
    echo -e "\t   info | show | lookup | mute | message | macro |"
    echo -e "\t   pushfile | collectProcessDataFiles | collectProcessPushDataFiles | pushurl | collectProcessPushDataFilesHTTP }"
    echo -e "\t version {AB}\t\t\t\t\t Show version of dvswitch.sh or Analog_Bridge"
    echo -e "\t mode {DMR|NXDN|P25|YSF|DSTAR} \t\t\t Set Analog_Bridge digital mode"
    echo -e "\t tune tg \t\t\t\t\t Tune to specific TG/Reflector"
    echo -e "\t ambesize {72|88|49}\t\t\t\t Set number of bits for ambe data"
    echo -e "\t ambemode {DMR|NXDN|P25|YSFN|YSFW|DSTAR} \t Set AMBE mode"
    echo -e "\t slot {1|2} \t\t\t\t\t Set DMR slot to transmit on"
    echo -e "\t update \t\t\t\t\t Update callsign and host databases"
    echo -e "\t tlvAudio mode gain\t\t\t\t Set AMBE audio mode and gain"
    echo -e "\t usrpAudio mode gain\t\t\t\t Set PCM audio mode and gain"
    echo -e "\t usrpAgc threshold slope decay\t\t\t Set PCM audio agc threshold slope and decay"
    echo -e "\t usrpCodec {SLIN|ULAW|ADPCM}\t\t\t Set AB -> DVSM/UC audio codec"
    echo -e "\t tlvPorts rxport txport\t\t\t\t Set Analog_Bridge receive and transmit ports"
    echo -e "\t info \t\t\t\t\t\t Update ABInfo and send to DVSM/UC"
    echo -e "\t show \t\t\t\t\t\t Pretty print the ABInfo json file"
    echo -e "\t lookup \t\t\t\t\t Lookup a DMR ID/call in the local database"
    echo -e "\t mute {OFF|USRP|TLV|BOTH}\t\t\t Cause Aanlog_Bridge to mute a stream"
    echo -e "\t message msg\t\t\t\t\t Send a text message to DVSM/UC"
    echo -e "\t macro {file|text}\t\t\t\t Send a macro collection to DVSM"
    echo -e "\t pushfile file\t\t\t\t\t Push file to DVSM"
    echo -e "\t pushurl url\t\t\t\t\t Push URL to DVSM"
    echo -e "\t collectProcessDataFiles \t\t\t Collect and prepare DVSM data files"
    echo -e "\t collectProcessPushDataFiles \t\t\t Collect, prepare and upload DVSM data files"
    echo -e "\t collectProcessPushDataFilesHTTP \t\t Collect, prepare and upload DVSM data files over http"
    echo -e "\t reloadDatabase \t\t\t\t Tell AB to reload database files into memory"
    exit 1
}

#################################################################
# The main application
#################################################################
if [ $# -eq 0 ]; then
    usage   # No arguments, so just report usage information
else
    case $1 in
        -h|--help|"-?"|help)
            usage
        ;;
        update)
            downloadDatabases
        ;;
        lookup)
            lookup $2
        ;;
        collectProcessDataFiles|collectprocessdatafiles|cpdf)
            collectProcessDataFiles
        ;;
        version|-v)
            if [ $# -eq 1 ]; then
                echo $SCRIPT_VERSION
            else
                getABInfoValue ab version
            fi
        ;;
        *)
            # All the commands below require that a valid ABInfo file exists.  
            TLV_PORT=`getTLVPort`   # Get the communications port to use before we go further
            if [ -z $TLV_PORT ]; then
                echo "Can not find /tmp/ABInfo file (have you run Analog_Brigde?), aborting" 
                exit 1
            fi
            case $1 in
                mode)
                    setMode $2
                ;;
                tune)
                    ${DEBUG} tune $2
                    ${DEBUG} getInfo
                ;;
                ambeSize|ambesize)
                    ${DEBUG} setAmbeSize $2
                ;;
                ambeMode|ambemode)
                    ${DEBUG} setAmbeMode $2
                ;;
                slot)
                    ${DEBUG} setSlot $2
                ;;
                setCallAndId|setcallandid)
                    setCallAndID $2 $3
                    getInfo
                ;;
                tlvAudio|tlvaudio)
                    setTLVAudioType $2
                    setTLVGain $3
                ;;
                usrpAudio|usrpaudio)
                    setUSRPAudioType $2
                    setUSRPGain $3
                ;;
                USRPAgc|usrpagc)
                    setUSRPAgc $2 $3 $4
                ;;
                TLVAgc|tlvagc)
                    setTLVAgc $2 $3 $4
                ;;
                usrpCodec|usrpcodec)
                    setUSRPCodec $2
                ;;
                tlvPorts|tlvports)
                    setTLVRxPort $2
                    setTLVTxPort $3
                ;;
                info)
                    # no arguments fill just tell AB to update the json file
                    # two arguments returns the value of "object" and "name" object{name:value}
                    getInfo $2 $3
                ;;
                show)
                    prettyPrintInfo
                ;;
                mute)
                    setMute $2
                ;;
                pushFile|pushfile|pf)
                    pushFileToClient "$2"
                ;;
                collectProcessPushDataFiles|collectprocesspushdatafiles|cppdf)
                    collectProcessPushDataFiles
                ;;
                pushUrl|pushurl)
                    pushURLToClient "$2"
                ;;
                collectProcessPushDataFilesHTTP|collectprocesspushdatafileshttp|cppdfh)
                    collectProcessPushDataFilesHTTP
                ;;
                reloadDatabase|reloaddatabase)
                    reloadDatabase
                ;;
                message)
                    sendMessage "$2"
                ;;
                macro)
                    sendMacro macro "$2"
                ;;
                menu)
                    sendMacro menu "$2"
                ;;
                ping)
                    setPingTimer "$2"
                ;;
                exitAB|exitab)
                    exitAnalogBridge $2 $3
                ;;
                usrpCommand|usrp)   # undocumented ATM/WIP
                    USRPCommand "$2" "$3"
                ;;
                *)
                    # unknown option, update branch info (no option is specified, just ordered by placement)
                    echo "Unknown command line option:" $1
                    usage
                ;;
            esac
                ;;
    esac
fi
exit $_ERRORCODE

#!/bin/bash

# Default topology number
TOPOLOGY_NUM=""

# Parse arguments
while getopts ":t:" opt; do
    case $opt in
        t)
            TOPOLOGY_NUM="$OPTARG"
            ;;
        \?)
            echo "Invalid option: -$OPTARG"
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument."
            exit 1
            ;;
    esac
done

# Check if topology number is provided
if [[ -z "$TOPOLOGY_NUM" ]]; then
    echo "Usage: $0 -t <topology_number>"
    exit 1
fi

# Set the IPLIST_FILE based on the topology number
IPLIST_FILE="vnltopo${TOPOLOGY_NUM}.iplist"

# Check if the file exists
if [[ ! -f "$IPLIST_FILE" ]]; then
    echo "File $IPLIST_FILE not found!"
    exit 1
fi

# Read the file and parse IP addresses
SERVER1_IP=""
SERVER2_IP=""
while IFS='=' read -r key value; do
    # Skip empty lines or lines without an equals sign
    if [[ -z "$key" || -z "$value" ]]; then
        continue
    fi

    # Extract the IP address
    IP=$(echo "$value" | xargs) # Trim whitespace

    # Identify server IPs
    if [[ "$key" == "ip_server1_eth0" ]]; then
        SERVER1_IP="$IP"
    elif [[ "$key" == "ip_server2_eth0" ]]; then
        SERVER2_IP="$IP"
    fi

    # Extract the descriptive information from the key
    if [[ "$key" =~ ip_(.+)_eth([0-9]+) ]]; then
        HOST=${BASH_REMATCH[1]} # e.g., vhost1
        INTERFACE=eth${BASH_REMATCH[2]} # e.g., eth0
    else
        HOST="unknown host"
        INTERFACE="unknown interface"
    fi

    # Display the descriptive message
    echo "====================================================="
    echo "Pinging interface $INTERFACE of $HOST at $IP..."
    echo "====================================================="

    # Ping the IP 10 times
    ping -c 10 "$IP"

    # Check if the ping was successful
    if [[ $? -eq 0 ]]; then
        echo "Ping to $IP successful."
    else
        echo "Ping to $IP failed."
    fi

    echo "-----------------------------------------------------"
done < "$IPLIST_FILE"

# Perform wget for both servers
if [[ -n "$SERVER1_IP" && -n "$SERVER2_IP" ]]; then
    echo "====================================================="
    echo "Downloading from server1 ($SERVER1_IP)..."
    wget http://"$SERVER1_IP":16280/64MB.bin

    echo "Downloading from server2 ($SERVER2_IP)..."
    wget http://"$SERVER2_IP":16280/64MB.bin
    echo "====================================================="
else
    echo "Error: Server IPs not found in $IPLIST_FILE"
    exit 1
fi

# Ping from server1 to server2
if [[ -n "$SERVER1_IP" && -n "$SERVER2_IP" ]]; then
    echo "====================================================="
    echo "Pinging from server1 to server2..."
    vnltopo${TOPOLOGY_NUM}.sh server1 ping -c 10 "$SERVER2_IP"

    echo "Pinging from server2 to server1..."
    vnltopo${TOPOLOGY_NUM}.sh server2 ping -c 10 "$SERVER1_IP"
    echo "====================================================="
else
    echo "Error: Server IPs not found for server-to-server ping."
    exit 1
fi

echo "All operations completed."
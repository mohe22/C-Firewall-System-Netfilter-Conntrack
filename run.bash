#!/bin/bash

# Configurable variables
SOURCE_FILES="interface.cpp firewall.cpp aclManager.cpp logger.cpp"
OUTPUT_BINARY="firewall"
QUEUE_RANGE="0:3"  

# Load kernel modules (ensure conntrack works)
load_kernel_modules() {
    echo "[+] Loading kernel modules..."
    sudo modprobe nf_conntrack
    sudo modprobe nfnetlink
    sudo modprobe nfnetlink_queue
}

# Cleanup iptables rules and delete the queue
cleanup() {
    echo "[+] Flushing all iptables rules..."
    sudo iptables -t mangle -F
    sudo iptables -t mangle -X
    echo "[+] Cleanup complete."
}

# Trap signals for cleanup
trap cleanup EXIT INT TERM

# Compile the firewall
echo "[+] Compiling ${SOURCE_FILES}..."
g++ -std=c++17 -Wall -Wextra $SOURCE_FILES -o $OUTPUT_BINARY \
    -lnetfilter_queue -lnfnetlink -lnetfilter_conntrack -lpthread \
     -lspdlog -lfmt
   

if [ $? -ne 0 ]; then
    echo "[!] Compilation failed."
    exit 1
fi

# Load required kernel modules
load_kernel_modules

# Set iptables rules (track all protocols, all conntrack states)
echo "[+] Adding iptables rules for ALL protocols and states..."

# PREROUTING (incoming packets)
sudo iptables -t mangle -A PREROUTING \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED,INVALID \
    -j NFQUEUE --queue-balance $QUEUE_RANGE

# OUTPUT (locally generated packets)
sudo iptables -t mangle -A OUTPUT \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED,INVALID \
    -j NFQUEUE --queue-balance $QUEUE_RANGE

# Run the binary
echo "[+] Running $OUTPUT_BINARY..."
sudo ./$OUTPUT_BINARY

echo "[+] Done."
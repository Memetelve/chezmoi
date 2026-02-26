#!/bin/bash
# Network upload/download speed monitor for Waybar

# Find active network interface
interface=$(ip route | grep '^default' | awk '{print $5}' | head -1)

if [ -z "$interface" ]; then
    echo "<span color='#89dceb'></span> 0 KB/s  <span color='#f9e2af'></span> 0 KB/s"
    exit 0
fi

# Get current stats
rx1=$(cat /sys/class/net/$interface/statistics/rx_bytes)
tx1=$(cat /sys/class/net/$interface/statistics/tx_bytes)
sleep 1
rx2=$(cat /sys/class/net/$interface/statistics/rx_bytes)
tx2=$(cat /sys/class/net/$interface/statistics/tx_bytes)

# Calculate speeds in KB/s
rx_speed=$(( (rx2 - rx1) / 1024 ))
tx_speed=$(( (tx2 - tx1) / 1024 ))

# Format output with appropriate units
if [ $rx_speed -gt 1024 ]; then
    rx_display=$(awk "BEGIN {printf \"%.1f MB/s\", $rx_speed/1024}")
else
    rx_display="${rx_speed} KB/s"
fi

if [ $tx_speed -gt 1024 ]; then
    tx_display=$(awk "BEGIN {printf \"%.1f MB/s\", $tx_speed/1024}")
else
    tx_display="${tx_speed} KB/s"
fi

echo "<span color='#89dceb'></span> ${rx_display}  <span color='#f9e2af'></span> ${tx_display}"

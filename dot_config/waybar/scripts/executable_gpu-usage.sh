#!/bin/bash
# GPU Usage script for Waybar
# Supports both NVIDIA and AMD GPUs

# Try AMD GPU first (check all card devices)
for card in /sys/class/drm/card*/device/gpu_busy_percent; do
    if [ -f "$card" ]; then
        usage=$(cat "$card" 2>/dev/null)
        if [ -n "$usage" ]; then
            echo "󰾲  ${usage}%"
            exit 0
        fi
    fi
done

# Try NVIDIA GPU
if command -v nvidia-smi &> /dev/null; then
    usage=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null)
    if [ -n "$usage" ]; then
        echo "󰾲  ${usage}%"
        exit 0
    fi
fi

# No GPU found
echo "󰾲  N/A"

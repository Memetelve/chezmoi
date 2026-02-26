#!/bin/bash
# GPU Temperature and Power script for Waybar

# Get GPU temperature
temp_file=$(find /sys/class/hwmon/hwmon*/temp*_label -exec grep -l "edge" {} \; 2>/dev/null | head -1)
if [ -n "$temp_file" ]; then
    temp_input="${temp_file/_label/_input}"
    temp=$(cat "$temp_input" 2>/dev/null)
    temp_c=$((temp / 1000))
else
    temp_c="N/A"
fi

# Get GPU power usage (AMD)
power_file="/sys/class/drm/card1/device/hwmon/hwmon3/power1_average"
if [ -f "$power_file" ]; then
    power_uw=$(cat "$power_file" 2>/dev/null)
    power_w=$((power_uw / 1000000))
    echo "  ${temp_c}°C  ${power_w}W"
else
    echo "  ${temp_c}°C"
fi

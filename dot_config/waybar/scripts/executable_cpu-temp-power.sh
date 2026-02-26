#!/bin/bash
# CPU Temperature and Power script for Waybar

# Get CPU temperature from thermal zone
temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
temp_c=$((temp / 1000))

# Get CPU power usage (Intel RAPL with sudo fallback or estimate)
if [ -r "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj" ]; then
    # Read energy twice with a delay to calculate power
    energy1=$(cat /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj 2>/dev/null)
    sleep 0.2
    energy2=$(cat /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj 2>/dev/null)
    
    if [ -n "$energy1" ] && [ -n "$energy2" ]; then
        # Calculate power in Watts
        energy_diff=$((energy2 - energy1))
        power_w=$((energy_diff / 200000))  # Convert to watts (0.2s interval)
        echo "  ${temp_c}°C  ${power_w}W"
    else
        echo "  ${temp_c}°C"
    fi
else
    # Fallback: estimate based on CPU usage (rough approximation)
    cpu_usage=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {printf "%.0f", usage}')
    # Estimate power (assuming ~125W TDP, scale by usage)
    power_w=$((cpu_usage * 125 / 100))
    echo "  ${temp_c}°C  ~${power_w}W"
fi

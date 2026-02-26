#!/usr/bin/env bash
set -euo pipefail

# swayidle -w \
#   timeout 120  'pgrep -x swaylock >/dev/null || nohup swaylock >/dev/null 2>&1 &' \
#   timeout 400  'hyprctl dispatch dpms off' \
#   timeout 1800 'systemctl suspend' \
#   resume       'hyprctl dispatch dpms on' \
#   before-sleep 'swaylock'

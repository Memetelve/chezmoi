#!/bin/bash

# Configuration
WALL_DIR="$HOME/.config/wallpapers"
THEME="$HOME/.config/rofi/wallpaper-grid.rasi"

# Check if swww is running
if ! swww query > /dev/null 2>&1; then
    swww-daemon &
    sleep 0.5
fi

# Get list of images and build Rofi rows directly.
# Using print0/read -d '' avoids malformed rows and phantom blank entries.

if [ ! -d "$WALL_DIR" ]; then
    exit 1
fi

mapfile -d '' -t FILES < <(find "$WALL_DIR" -type f \( -iname "*.jpg" -o -iname "*.png" -o -iname "*.webp" -o -iname "*.jpeg" \) -print0 | sort -z)

[ "${#FILES[@]}" -gt 0 ] || exit 0

# Show Rofi and get selection
CHOICE=$(for line in "${FILES[@]}"; do
    filename=$(basename "$line")
    printf '%s\0icon\x1f%s\n' "$filename" "$line"
done | rofi -dmenu -config "$THEME" -i -p "󰸉 Wallpapers")

# If user made a choice, apply it
if [ -n "$CHOICE" ]; then
    SELECTED_FILE=""
    for line in "${FILES[@]}"; do
        if [ "$(basename "$line")" = "$CHOICE" ]; then
            SELECTED_FILE="$line"
            break
        fi
    done

    [ -n "$SELECTED_FILE" ] || SELECTED_FILE="$WALL_DIR/$CHOICE"

    swww img "$SELECTED_FILE" \
        --transition-type grow \
        --transition-fps 60 \
        --transition-duration 1.5 \
        --transition-pos 0.85,0.85
fi

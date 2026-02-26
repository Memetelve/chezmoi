#!/bin/bash
# Thunderbird unread email counter for Waybar

# Find Thunderbird profile directory
PROFILE_DIR=$(find ~/.thunderbird -maxdepth 1 -type d -name "*.default*" | head -1)

if [ -z "$PROFILE_DIR" ]; then
    echo " 0"
    exit 0
fi

# Count unread messages from global-messages-db.sqlite
DB_FILE="$PROFILE_DIR/global-messages-db.sqlite"

if [ ! -f "$DB_FILE" ]; then
    echo " 0"
    exit 0
fi

# Query unread count
UNREAD=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM messages WHERE read = 0 AND folderID NOT IN (SELECT id FROM folderLocations WHERE folderURI LIKE '%Trash%' OR folderURI LIKE '%Spam%' OR folderURI LIKE '%Junk%');" 2>/dev/null)

if [ -z "$UNREAD" ] || [ "$UNREAD" = "" ]; then
    UNREAD=0
fi

# Color output based on unread count
if [ "$UNREAD" -gt 0 ]; then
    echo "<span color='#f9e2af'></span> $UNREAD"
else
    echo " $UNREAD"
fi

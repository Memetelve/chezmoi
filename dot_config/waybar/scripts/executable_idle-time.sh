#!/usr/bin/env bash
set -euo pipefail

USER_NAME="$(id -un)"

# 1) Prefer XDG_SESSION_ID if present
if [ -n "${XDG_SESSION_ID-}" ]; then
  session="$XDG_SESSION_ID"
else
  # 2) Try to find a session by username
  session=$(loginctl list-sessions --no-legend 2>/dev/null \
    | awk -v u="$USER_NAME" '$2==u {print $1; exit}')

  # 3) If that failed, try loginctl show-user to get Sessions list
  if [ -z "$session" ]; then
    sessions_list=$(loginctl show-user "$USER_NAME" -p Sessions --value 2>/dev/null || true)
    # sessions_list might be "2 3", pick first token if present
    session=$(printf '%s' "$sessions_list" | awk '{print $1}')
  fi
fi

if [ -z "$session" ]; then
  echo "no session"
  exit 1
fi

idle_usec=$(loginctl show-session "$session" -p IdleSinceHint --value 2>/dev/null || true)

if [ -z "$idle_usec" ] || [ "$idle_usec" = "0" ]; then
  echo "0s"
  exit 0
fi

now_sec=$(date +%s)
idle_sec=$(( now_sec - idle_usec / 1000000 ))

if [ "$idle_sec" -lt 60 ]; then
  echo "${idle_sec}s"
elif [ "$idle_sec" -lt 3600 ]; then
  printf '%dm%02ds\n' $((idle_sec/60)) $((idle_sec%60))
else
  printf '%dh%02dm\n' $((idle_sec/3600)) $(((idle_sec%3600)/60))
fi

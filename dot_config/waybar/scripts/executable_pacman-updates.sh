#!/usr/bin/env bash
set -euo pipefail

# Waybar pacman + AUR updates script
# Outputs JSON: {"text": "...", "tooltip": "..."}

json_quote() {
  # Quote stdin as a JSON string. Prefer python3 if available.
  if command -v python3 >/dev/null 2>&1; then
    # Read from stdin in python (using -c so stdin is available).
    python3 -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))'
  else
    local s
    s=$(cat)
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    printf '"%s"' "$s"
  fi
}

# Get official updates (checkupdates recommended)
official_raw=""
if command -v checkupdates >/dev/null 2>&1; then
  official_raw=$(checkupdates 2>/dev/null || true)
else
  official_raw=$(pacman -Qu 2>/dev/null || true)
fi

official_list=$(printf "%s\n" "$official_raw" | sed '/^\s*$/d')

official_count=0
if [[ -n "$official_list" ]]; then
  official_count=$(printf "%s\n" "$official_list" | wc -l | tr -d ' ')
fi

# Detect AUR helper
aur_helper=""
for h in paru yay pikaur pamac; do
  if command -v "$h" >/dev/null 2>&1; then
    aur_helper="$h"
    break
  fi
done

aur_list=""
aur_count=0
if [[ -n "$aur_helper" ]]; then
  case "$aur_helper" in
    paru|yay|pikaur)
      aur_list=$("$aur_helper" -Qua 2>/dev/null || true)
      ;;
    pamac)
      aur_list=$("$aur_helper" checkupdates --aur 2>/dev/null || true)
      ;;
    *)
      aur_list=$("$aur_helper" -Qua 2>/dev/null || true)
      ;;
  esac
  aur_list=$(printf "%s\n" "$aur_list" | sed '/^\s*$/d')
  if [[ -n "$aur_list" ]]; then
    aur_count=$(printf "%s\n" "$aur_list" | wc -l | tr -d ' ')
  fi
fi

# Group official packages by repository
declare -A repo_pkgs
declare -A repo_count

if [[ -n "$official_list" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    pkg=$(awk '{print $1}' <<<"$line")
    [[ -z "$pkg" ]] && continue
    repo=$(pacman -Si "$pkg" 2>/dev/null | awk -F': ' \
           '/^Repository/{print $2; exit}')
    [[ -z "$repo" ]] && repo="unknown"
    repo_pkgs["$repo"]+="$line"$'\n'
    repo_count["$repo"]=$(( ${repo_count["$repo"]:-0} + 1 ))
  done <<<"$official_list"
fi

# Build tooltip
tooltip=""
if (( official_count > 0 )); then
  tooltip+="Official upgrades ($official_count):"$'\n'
  for r in core extra community multilib; do
    if [[ ${repo_count[$r]:-0} -gt 0 ]]; then
      tooltip+=$'\n'"$r (${repo_count[$r]}):"$'\n'
      tooltip+="${repo_pkgs[$r]}"
    fi
  done
  for r in "${!repo_count[@]}"; do
    case "$r" in
      core|extra|community|multilib) continue ;;
    esac
    tooltip+=$'\n'"$r (${repo_count[$r]}):"$'\n'
    tooltip+="${repo_pkgs[$r]}"
  done
fi

if (( aur_count > 0 )); then
  tooltip+=$'\n\n'"AUR upgrades ($aur_count):"$'\n'
  tooltip+="$aur_list"
fi

if [[ -z "$tooltip" ]]; then
  tooltip="Up to date"
fi

# Short text for the bar. Show official|aur if AUR present, otherwise official.
icon="  "
if (( aur_count > 0 )); then
  text="$icon ${official_count}|${aur_count}"
else
  text="$icon ${official_count}"
fi

# Output JSON
printf '{"text": %s, "tooltip": %s}\n' \
  "$(printf "%s" "$text" | json_quote)" \
  "$(printf "%s" "$tooltip" | json_quote)"

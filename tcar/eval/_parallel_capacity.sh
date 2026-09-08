#!/usr/bin/env bash
cd /mnt/c/Users/SK/CTI-Chatbot
echo "=== active eval procs ==="
pgrep -af 'run_counterfactual|python -m tcar' || echo none
echo
echo "=== count ==="
echo -n "counterfactual: "; pgrep -c -f 'run_counterfactual' || echo 0
echo
echo "=== load / mem ==="
uptime
free -h 2>/dev/null | head -3 || true
echo
echo "=== open files / python rss (top) ==="
ps -eo pid,rss,pcpu,cmd --sort=-rss | grep -E 'run_counterfactual|python -m tcar' | grep -v grep | head -10
echo
# rough RSS MB
ps -eo rss,cmd | grep run_counterfactual | grep -v grep | awk '{s+=$1} END {printf "total_cf_rss_mb≈%.0f\n", s/1024}'

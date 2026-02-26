#!/usr/bin/env bash
set -euo pipefail

# --- Configuration ---
SESSION="fuzz"
NUM_SECONDARY=15  # secondary instances (total = 1 main + N secondary)

COMMON_ARGS=(
    fuzz
    --engine afl
    --config configs/cve-2022-23943/httpd.conf
    --mutator grammar_mutator/custom_mutators/grammar_mutator/grammar_mutator/libgrammarmutator-http.so
    --grammar src/apatchy/grammars/http.json
    --suppress configs/ubsan.supp
    --output-dir afl-out-sed-overflow-works
    --timeout 120
)

# Kill existing session if any
if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "Session '${SESSION}' already exists. Kill it first with: tmux kill-session -t ${SESSION}"
    exit 1
fi

# Create a detached tmux session with the main instance
echo "[*] Starting main instance: main01"
tmux new-session -d -s "$SESSION" -n "main01" \
    "apatchy ${COMMON_ARGS[*]} --role main --name main01"

sleep 2  # let main start and generate seeds first

# Launch secondary instances in new windows
for i in $(seq -w 1 "$NUM_SECONDARY"); do
    name="sec${i}"
    echo "[*] Starting secondary instance: ${name}"
    tmux new-window -t "$SESSION" -n "$name" \
        "apatchy ${COMMON_ARGS[*]} --role secondary --name $name"
    sleep 0.5
done

echo
echo "[+] Launched 1 main + ${NUM_SECONDARY} secondary instances in tmux session '${SESSION}'"
echo
echo "    tmux attach -t ${SESSION}       # attach"
echo "    Ctrl-b n / Ctrl-b p             # next/prev window"
echo "    Ctrl-b w                        # list windows"
echo "    Ctrl-b d                        # detach"
echo "    tmux kill-session -t ${SESSION}   # kill all"

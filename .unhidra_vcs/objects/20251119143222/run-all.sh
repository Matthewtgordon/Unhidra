#!/usr/bin/env bash

SESSION="unhidra-ms"

tmux has-session -t $SESSION 2>/dev/null
if [ $? -eq 0 ]; then
    echo "Killing existing session $SESSION..."
    tmux kill-session -t $SESSION
fi

echo "Starting new tmux session: $SESSION"

# GATEWAY
tmux new-session -d -s $SESSION -n gateway
tmux send-keys -t $SESSION:0 "cd ~/unhidra-rust/gateway-service && cargo run" C-m

# AUTH-API (REAL LOGIN SERVER)
tmux new-window -t $SESSION -n auth-api
tmux send-keys -t $SESSION:1 "cd ~/unhidra-rust/auth-api && cargo run" C-m

# CHAT
tmux new-window -t $SESSION -n chat
tmux send-keys -t $SESSION:2 "cd ~/unhidra-rust/chat-service && cargo run" C-m

# HISTORY
tmux new-window -t $SESSION -n history
tmux send-keys -t $SESSION:3 "cd ~/unhidra-rust/history-service && cargo run" C-m

# PRESENCE
tmux new-window -t $SESSION -n presence
tmux send-keys -t $SESSION:4 "cd ~/unhidra-rust/presence-service && cargo run" C-m

# BOT
tmux new-window -t $SESSION -n bot
tmux send-keys -t $SESSION:5 "cd ~/unhidra-rust/bot-service && cargo run" C-m

echo "All microservices launched."
echo "Attach with:   tmux attach -t $SESSION"

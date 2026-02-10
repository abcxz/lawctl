#!/bin/bash
# Mock agent script that simulates AI agent tool calls through the gateway.
# Used for end-to-end testing of lawctl.
#
# This script sends JSON requests over the lawctl Unix socket and
# prints the responses. It simulates a typical agent session:
# 1. Write to a safe path (should be allowed)
# 2. Write to .env (should be denied)
# 3. Delete a file (should be denied)
# 4. Run a safe command (should be allowed)
# 5. Run a dangerous command (should be denied)
# 6. Git push (should require approval)

SOCKET="${LAWCTL_SOCKET:-/tmp/lawctl.sock}"

send_request() {
    local request="$1"
    echo "$request" | socat - UNIX-CONNECT:"$SOCKET"
}

echo "=== Mock Agent Starting ==="
echo "Socket: $SOCKET"

# 1. Write to src/main.rs (allowed)
echo "--- Test 1: Write to src/main.rs ---"
send_request '{"request_id":"req-1","action":"write","target":"src/main.rs","payload":"fn main() { println!(\"hello\"); }"}'

# 2. Write to .env (denied)
echo "--- Test 2: Write to .env ---"
send_request '{"request_id":"req-2","action":"write","target":".env","payload":"SECRET_KEY=abc123"}'

# 3. Delete src/config.rs (denied — not in /tmp)
echo "--- Test 3: Delete src/config.rs ---"
send_request '{"request_id":"req-3","action":"delete","target":"src/config.rs"}'

# 4. Run safe command (allowed)
echo "--- Test 4: Run cargo build ---"
send_request '{"request_id":"req-4","action":"run_cmd","target":"shell","payload":"cargo build"}'

# 5. Run dangerous command (denied)
echo "--- Test 5: Run rm -rf / ---"
send_request '{"request_id":"req-5","action":"run_cmd","target":"shell","payload":"rm -rf /"}'

# 6. Git push (requires approval)
echo "--- Test 6: Git push main ---"
send_request '{"request_id":"req-6","action":"git_push","target":"main"}'

echo "=== Mock Agent Done ==="

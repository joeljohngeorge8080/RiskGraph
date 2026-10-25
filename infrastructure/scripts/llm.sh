#!/usr/bin/env bash
# The local explanation model's lifecycle, tied to the RiskGraph stack (ADR-0016).
#
#   llm.sh up       load the model (resident until `down`) and expose Ollama as a socket
#   llm.sh down     unload the model and remove the socket
#   llm.sh status   what is loaded, on which processor, and whether containers can reach it
#
# Ollama itself keeps running as a host service and listens on 127.0.0.1 only. Containers
# cannot use that (and a host firewall such as ufw may drop container-to-host TCP anyway),
# so `up` runs socat to publish it as .data/ollama/ollama.sock, which Compose mounts into
# the api and worker. Ollama puts as many layers as fit on the GPU and the rest on the CPU.
#
# Nothing here is fatal: when Ollama, the model or socat is missing, RiskGraph still starts
# and explanations use the template.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOCK_DIR="$ROOT/.data/ollama" # the path docker-compose.yml mounts
SOCK="$SOCK_DIR/ollama.sock"
PID_FILE="$SOCK_DIR/socat.pid"
PRELOAD_PID_FILE="$SOCK_DIR/preload.pid"
HOST_URL="http://127.0.0.1:11434"

# Environment wins, then .env, then the default (same names as the backend settings).
setting() {
  local value="${!1:-}"
  [ -z "$value" ] && [ -f "$ROOT/.env" ] && value="$(sed -n "s/^$1=//p" "$ROOT/.env" | tail -n 1)"
  printf '%s' "${value:-$2}"
}

PROVIDER="$(setting RISKGRAPH_LLM_PROVIDER ollama)"
MODEL="$(setting RISKGRAPH_OLLAMA_MODEL qwen3:4b)"

say() { printf '[llm] %s\n' "$*"; }

ollama_up() { curl -s -m 3 "$HOST_URL/api/version" >/dev/null; }
socket_up() { curl -s -m 3 --unix-socket "$SOCK" http://ollama/api/version >/dev/null; }

up() {
  # Created for every run: Docker would otherwise create the bind-mount source as root.
  mkdir -p "$SOCK_DIR" && chmod 755 "$SOCK_DIR"
  if [ "$PROVIDER" != "ollama" ]; then say "RISKGRAPH_LLM_PROVIDER=$PROVIDER: not starting a model"; return 0; fi
  if ! ollama_up; then
    say "Ollama is not answering on $HOST_URL: explanations will use the template"
    return 0
  fi
  if ! curl -s -m 3 "$HOST_URL/api/tags" | grep -q "\"name\":\"$MODEL\""; then
    say "model $MODEL is not installed (ollama pull $MODEL): explanations will use the template"
    return 0
  fi
  socket_forward
  # Loading takes several seconds; do it in the background so the stack is not held up.
  # keep_alive -1 (a number: Ollama rejects the string "-1") keeps it loaded until `down`.
  curl -s -m 300 "$HOST_URL/api/generate" \
    -d "{\"model\":\"$MODEL\",\"prompt\":\"\",\"keep_alive\":-1}" >/dev/null 2>&1 &
  echo $! >"$PRELOAD_PID_FILE"
  say "loading $MODEL (GPU first, CPU for what does not fit); check with: make llm-status"
}

socket_forward() {
  if ! command -v socat >/dev/null; then
    say "socat is not installed: containers cannot reach Ollama, so explanations use the template"
    return 0
  fi
  stop_forwarder # a leftover from a crashed run
  # 0666 on the socket: the container user is not this user. Ollama has no authentication;
  # it already answers every local user on 127.0.0.1, and this adds nothing beyond that.
  nohup socat "UNIX-LISTEN:$SOCK,fork,mode=0666,unlink-early" "TCP:127.0.0.1:11434" \
    >"$SOCK_DIR/socat.log" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 0.3
  if socket_up; then
    say "containers reach Ollama through $SOCK"
  else
    say "forwarder did not start (see $SOCK_DIR/socat.log): explanations will use the template"
  fi
}

stop_forwarder() {
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE")"
    # Only kill what we started: the pid may have been reused since.
    if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q "socat UNIX-LISTEN:$SOCK"; then
      kill "$pid" && say "stopped the Ollama forwarder"
    fi
    rm -f "$PID_FILE"
  fi
  rm -f "$SOCK"
}

loaded() { curl -s -m 3 "$HOST_URL/api/ps" | grep -q "\"name\":\"$MODEL\""; }

down() {
  cancel_preload
  if [ "$PROVIDER" = "ollama" ] && ollama_up; then
    # A load that was still in flight can finish after the first unload, so ask until
    # Ollama no longer lists the model.
    local try
    for try in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      curl -s -m 30 "$HOST_URL/api/generate" \
        -d "{\"model\":\"$MODEL\",\"prompt\":\"\",\"keep_alive\":0}" >/dev/null
      loaded || break
      sleep 1
    done
    if loaded; then say "$MODEL is still loaded: run 'ollama stop $MODEL'"; else say "unloaded $MODEL"; fi
  fi
  stop_forwarder
}

cancel_preload() {
  [ -f "$PRELOAD_PID_FILE" ] || return 0
  local pid
  pid="$(cat "$PRELOAD_PID_FILE")"
  # Only kill what we started: the pid may have been reused since.
  if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q "/api/generate"; then
    kill "$pid" 2>/dev/null
  fi
  rm -f "$PRELOAD_PID_FILE"
}

status() {
  command -v ollama >/dev/null && ollama ps
  if [ -S "$SOCK" ] && socket_up; then
    say "containers can reach Ollama through $SOCK"
  else
    say "Ollama is NOT reachable from containers (no working socket at $SOCK)"
  fi
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac

#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/cpu_core_tester"

if [ ! -f "$BIN" ]; then
    echo "Building..."
    echo "WARNING: if this host is the SUSPECT machine, do not trust a binary built"
    echo "         here - the compiler itself runs on possibly-failing cores. Prefer"
    echo "         'make static' on a trusted machine, copy the binary over, and"
    echo "         verify its SHA256 (sha256sum $BIN) before running."
    make -C "$DIR"
fi

usage() {
    cat <<EOF
Compression Pipeline Corruption Tester

Mirrors Docker pull: compress -> decompress -> SHA256 verify.
Pins one thread per core to isolate which core causes corruption.

Usage: $0 <command>

Commands:
  build         Build the tester
  deps          Install build dependencies
  check         Check if dependencies are installed

  quick         1 iteration, all cores, all algs, both modes
  standard      100 iterations
  soak          1000 iterations
  overnight [H] Timed soak: loop until H hours elapse (default 8), log to file.
                Each pass = long parallel stress + short sequential isolation.
  docker        100 iterations, 4MB blocks (mimics typical Docker layer chunk)
  kat [I]       Known-answer test: verify against golden digests precomputed
                on a trusted machine (default 100 iterations, fixed 4MB block)
  vote [I]      Cross-core voting screen: all cores run identical input,
                majority rules on compressed digests (default 100 rounds).
                Writes a digest log for offline verification.

  sequential    Sequential only (one core at a time, identifies bad core)
  parallel      Parallel only (all cores at once, finds errors under load)

  core N        Test a specific core (default 100 iterations)
  core-soak N   Soak a specific core (1000 iterations)

  help          This message
EOF
}

case "${1:-help}" in
    build)    make -C "$DIR" ;;
    deps)     make -C "$DIR" deps ;;
    check)    make -C "$DIR" check-deps ;;
    quick)    "$BIN" -m both -i 1 -a all -v ;;
    standard) "$BIN" -m both -i 100 -a all ;;
    soak)     "$BIN" -m both -i 1000 -a all ;;
    overnight)
        HOURS="${2:-8}"
        LOG="$DIR/soak_$(date +%Y%m%d_%H%M%S).log"
        END=$(( $(date +%s) + HOURS * 3600 ))
        PASS=0
        echo "Overnight soak: ${HOURS}h, logging to $LOG"
        {
            echo "===== soak start: $(date -Is) | host: $(hostname) | ${HOURS}h ====="
            while [ "$(date +%s)" -lt "$END" ]; do
                PASS=$((PASS + 1))
                echo ""
                echo "===== pass $PASS | $(date -Is) ====="
                "$BIN" -m parallel -i 200 -a all || true
                "$BIN" -m sequential -i 20 -a all || true
            done
            echo ""
            echo "===== soak end: $(date -Is) | passes: $PASS ====="
        } 2>&1 | tee "$LOG"
        echo ""
        CORR=$(grep -c CORRUPTION "$LOG" || true)
        echo "RESULT: $CORR corruption events (log: $LOG)"
        ;;
    docker)   "$BIN" -m both -i 100 -s 4 -a all ;;
    kat)      "$BIN" -m both -i "${2:-100}" -a all -k ;;
    vote)     "$BIN" -m parallel -V -i "${2:-100}" -a all \
                --digest-log "$DIR/vote_$(date +%Y%m%d_%H%M%S).log" ;;
    sequential) "$BIN" -m sequential -i 100 -a all -v ;;
    parallel) "$BIN" -m parallel -i 100 -a all -v ;;
    core)
        [ -z "$2" ] && { echo "Usage: $0 core <N> [iterations]"; exit 1; }
        "$BIN" -m sequential -c 1 -o "$2" -i "${3:-100}" -a all -v
        ;;
    core-soak)
        [ -z "$2" ] && { echo "Usage: $0 core-soak <N> [iterations]"; exit 1; }
        "$BIN" -m sequential -c 1 -o "$2" -i "${3:-1000}" -a all -v
        ;;
    help|-h|--help) usage ;;
    *) echo "Unknown command: $1"; usage; exit 1 ;;
esac

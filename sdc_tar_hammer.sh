#!/usr/bin/env bash
#
# sdc_tar_hammer.sh - Hammer a set of logical CPUs with tar+compression and
# verify data integrity via SHA-256 to catch silent data corruption (SDC).
#
# Only requires: bash, tar, xz/gzip/bzip2, sha256sum, taskset, dd.
#
# Method:
#   1. Build a fixed payload once and record its trusted SHA-256 (reference).
#   2. Spawn N workers, all pinned (taskset) to the target CPUs.
#   3. Each worker loops: tar+compress the payload, decompress it back, and
#      sha256 the result. The compressor's own CRC (xz=CRC64, gzip=CRC32) is a
#      second independent check. A checksum mismatch or a decompressor error is
#      a wrong-answer produced by the CPU = an SDC hit.
#
# A healthy core produces zero hits. A mercurial/defective core produces hits
# that reproduce when pinned to it and vanish when pinned elsewhere.

set -u

CPUS="70,71"
DURATION=60
WORKERS=0
PAYLOAD_MB=32
METHOD="xz"

usage() {
    cat <<EOF
Usage: $0 [-c cpu_list] [-t seconds] [-w workers] [-s payload_mb] [-m method]
  -c  Comma/range CPU list for taskset      (default: $CPUS)
  -t  Duration in seconds                    (default: $DURATION)
  -w  Concurrent workers (0 = one per CPU)   (default: auto)
  -s  Payload size in MiB                     (default: $PAYLOAD_MB)
  -m  Compressor: xz | gzip | bzip2          (default: $METHOD)
EOF
    exit 1
}

while getopts "c:t:w:s:m:h" opt; do
    case "$opt" in
        c) CPUS="$OPTARG" ;;
        t) DURATION="$OPTARG" ;;
        w) WORKERS="$OPTARG" ;;
        s) PAYLOAD_MB="$OPTARG" ;;
        m) METHOD="$OPTARG" ;;
        *) usage ;;
    esac
done

case "$METHOD" in
    xz)    ZFLAG="-J" ;;
    gzip)  ZFLAG="-z" ;;
    bzip2) ZFLAG="-j" ;;
    *) echo "Unknown method: $METHOD" >&2; exit 1 ;;
esac

command -v "$METHOD" >/dev/null 2>&1 || { echo "Missing compressor: $METHOD" >&2; exit 1; }

# Count CPUs in the list to size worker pool.
ncpu_in_list() {
    local c n=0
    IFS=',' read -ra parts <<< "$1"
    for c in "${parts[@]}"; do
        if [[ "$c" == *-* ]]; then
            n=$(( n + ${c#*-} - ${c%-*} + 1 ))
        else
            n=$(( n + 1 ))
        fi
    done
    echo "$n"
}

if [[ "$WORKERS" -le 0 ]]; then
    WORKERS=$(( $(ncpu_in_list "$CPUS") * 2 ))
fi

# Prefer tmpfs so we stay CPU-bound, not disk-bound.
if [[ -d /dev/shm && -w /dev/shm ]]; then
    BASE="/dev/shm/sdc_hammer.$$"
else
    BASE="/tmp/sdc_hammer.$$"
fi
DATADIR="$BASE/data"
WORKDIR="$BASE/work"
mkdir -p "$DATADIR" "$WORKDIR"

cleanup() { rm -rf "$BASE"; }
trap cleanup EXIT

echo "=================================================================="
echo " SDC tar/compression hammer"
echo "   CPUs        : $CPUS"
echo "   Duration    : ${DURATION}s"
echo "   Workers     : $WORKERS"
echo "   Payload     : ${PAYLOAD_MB} MiB"
echo "   Compressor  : $METHOD"
echo "   Scratch     : $BASE"
echo "=================================================================="

# Build a compressible-but-nontrivial payload: tile a random seed block so the
# compressor has to do real match-finding work (heavy integer path).
SEED="$DATADIR/seed"
PAYLOAD="$DATADIR/payload"
dd if=/dev/urandom of="$SEED" bs=1M count=4 status=none
: > "$PAYLOAD"
tiles=$(( PAYLOAD_MB / 4 ))
[[ "$tiles" -lt 1 ]] && tiles=1
for ((i=0; i<tiles; i++)); do cat "$SEED" >> "$PAYLOAD"; done

# Trusted reference checksum (reading a file back does not involve the ALU/FPU
# math paths that SDC corrupts, so this is our ground truth).
REF=$(sha256sum "$PAYLOAD" | awk '{print $1}')
echo "Reference SHA-256: $REF"
echo "Starting workers..."

worker() {
    local id="$1"
    local deadline="$2"
    local iters=0 hits=0
    local errlog="$WORKDIR/w${id}.err"
    local got

    while [[ "$(date +%s)" -lt "$deadline" ]]; do
        # tar+compress the payload, then decompress it straight back and hash.
        got=$(tar -c $ZFLAG -C "$DATADIR" payload 2>>"$errlog" \
              | tar -x $ZFLAG -O 2>>"$errlog" \
              | sha256sum 2>>"$errlog" | awk '{print $1}')

        if [[ "$got" != "$REF" ]]; then
            hits=$((hits+1))
            echo "[$(date +%T)] worker $id iter $iters MISMATCH got=$got" >> "$errlog"
        fi
        iters=$((iters+1))
    done
    echo "$id $iters $hits" > "$WORKDIR/w${id}.result"
}

# Export function + all state so each taskset-pinned child bash inherits them.
export -f worker
export DATADIR WORKDIR ZFLAG REF

END=$(( $(date +%s) + DURATION ))
for ((w=0; w<WORKERS; w++)); do
    taskset -c "$CPUS" bash -c "worker $w $END" &
done
wait

TOTAL_ITERS=0
TOTAL_HITS=0
for f in "$WORKDIR"/w*.result; do
    [[ -e "$f" ]] || continue
    read -r wid witers whits < "$f"
    TOTAL_ITERS=$(( TOTAL_ITERS + witers ))
    TOTAL_HITS=$(( TOTAL_HITS + whits ))
done

CRC_ERRS=$(cat "$WORKDIR"/*.err 2>/dev/null | grep -ciE 'corrupt|crc|error|unexpected end' )

echo "=================================================================="
echo " RESULTS for CPUs $CPUS"
echo "   Total iterations : $TOTAL_ITERS"
echo "   Checksum hits    : $TOTAL_HITS"
echo "   Decompressor errs: $CRC_ERRS"
echo "=================================================================="
if [[ "$TOTAL_HITS" -gt 0 || "$CRC_ERRS" -gt 0 ]]; then
    echo " VERDICT: SDC DETECTED on CPUs $CPUS"
    cat "$WORKDIR"/*.err 2>/dev/null | grep -iE 'MISMATCH|corrupt|crc|error' | head -20
    exit 2
else
    echo " VERDICT: clean (no corruption observed)"
    exit 0
fi

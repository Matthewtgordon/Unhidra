#!/usr/bin/env bash
set -e

ROOT="$HOME/unhidra-rust"
VCSDIR="$ROOT/.unhidra_vcs"
OBJDIR="$VCSDIR/objects"
LOGFILE="$VCSDIR/log"

mkdir -p "$OBJDIR"

hash_file() {
    sha256sum "$1" | awk '{print $1}'
}

save_snapshot() {
    echo "Saving snapshot..."
    SNAP_ID=$(date +%Y%m%d%H%M%S)
    SNAP_DIR="$OBJDIR/$SNAP_ID"
    mkdir "$SNAP_DIR"

    find "$ROOT" -type f \
        ! -path "$ROOT/.unhidra_vcs/*" \
        ! -path "$ROOT/target/*" \
        | while read -r FILE; do

        REL="${FILE#$ROOT/}"
        DEST="$SNAP_DIR/$REL"
        mkdir -p "$(dirname "$DEST")"
        cp "$FILE" "$DEST"
    done

    echo "$SNAP_ID" >> "$LOGFILE"
    echo "Snapshot saved: $SNAP_ID"
}

list_snapshots() {
    cat "$LOGFILE"
}

diff_snapshots() {
    A="$OBJDIR/$1"
    B="$OBJDIR/$2"

    [ ! -d "$A" ] && { echo "Snapshot $1 missing"; exit 1; }
    [ ! -d "$B" ] && { echo "Snapshot $2 missing"; exit 1; }

    diff -ruN "$A" "$B" || true
}

checkout_snapshot() {
    SNAP="$OBJDIR/$1"
    [ ! -d "$SNAP" ] && { echo "Snapshot $1 missing"; exit 1; }

    echo "Restoring snapshot $1..."

    find "$ROOT" -type f \
        ! -path "$ROOT/.unhidra_vcs/*" \
        ! -path "$ROOT/target/*" \
        -exec rm {} \;

    cp -r "$SNAP/"* "$ROOT/"
    echo "Done."
}

case "$1" in
    save) save_snapshot ;;
    list) list_snapshots ;;
    diff) diff_snapshots "$2" "$3" ;;
    checkout) checkout_snapshot "$2" ;;
    *)
        echo "Commands:"
        echo "  save"
        echo "  list"
        echo "  diff <id1> <id2>"
        echo "  checkout <id>"
        ;;
esac

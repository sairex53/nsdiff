#!/usr/bin/env bash

set -euo pipefail


if (( $# != 1 )); then
    echo "usage: $0 NSDIFF" >&2
    exit 1
fi


NSDIFF_ARG="$1"

if [[ "$NSDIFF_ARG" = /* ]]; then
    NSDIFF="$NSDIFF_ARG"
else
    NSDIFF="$PWD/$NSDIFF_ARG"
fi


fail()
{
    echo "snapshot-atomic test failed: $*" >&2
    exit 1
}


tmpdir="$(
    mktemp \
        -d \
        /tmp/nsdiff-snapshot-atomic.XXXXXX
)"

snapshot="$tmpdir/process.nsnap"
victim="$tmpdir/victim.txt"
link_snapshot="$tmpdir/link.nsnap"
missing_parent_snapshot="$tmpdir/missing/process.nsnap"


cleanup()
{
    rm -rf \
        "$tmpdir"
}


trap cleanup EXIT


#
# Normal capture must create a valid snapshot.
#

"$NSDIFF" \
    --capture \
    "$snapshot" \
    "$$" \
    >/dev/null \
    || fail \
        "normal capture failed"


"$NSDIFF" \
    --verify-snapshot \
    "$snapshot" \
    >/dev/null \
    || fail \
        "new snapshot does not verify"


#
# Snapshot files contain process environment/security state.
# They must always be private to the owner.
#

mode="$(
    stat \
        -c '%a' \
        "$snapshot"
)"


if [[ "$mode" != "600" ]]; then
    fail \
        "snapshot mode is $mode instead of 600"
fi


#
# Replacing an existing snapshot must still leave a valid 0600 file.
#

"$NSDIFF" \
    --capture \
    "$snapshot" \
    "$$" \
    >/dev/null \
    || fail \
        "atomic replacement capture failed"


"$NSDIFF" \
    --verify-snapshot \
    "$snapshot" \
    >/dev/null \
    || fail \
        "replaced snapshot does not verify"


mode="$(
    stat \
        -c '%a' \
        "$snapshot"
)"


if [[ "$mode" != "600" ]]; then
    fail \
        "replaced snapshot mode is $mode instead of 600"
fi


#
# A destination symlink must be replaced as a directory entry.
# The symlink target itself must never be truncated or modified.
#

printf '%s\n' \
    'DO_NOT_TOUCH_NSDIFF_VICTIM' \
    >"$victim"


ln -s \
    "$victim" \
    "$link_snapshot"


"$NSDIFF" \
    --capture \
    "$link_snapshot" \
    "$$" \
    >/dev/null \
    || fail \
        "capture over destination symlink failed"


if [[ -L "$link_snapshot" ]]; then
    fail \
        "destination is still a symlink after capture"
fi


if [[ ! -f "$link_snapshot" ]]; then
    fail \
        "destination was not replaced by a regular snapshot"
fi


victim_contents="$(
    cat \
        "$victim"
)"


if [[ "$victim_contents" != \
      "DO_NOT_TOUCH_NSDIFF_VICTIM" ]]; then

    fail \
        "symlink target was modified"
fi


"$NSDIFF" \
    --verify-snapshot \
    "$link_snapshot" \
    >/dev/null \
    || fail \
        "snapshot replacing symlink does not verify"


mode="$(
    stat \
        -c '%a' \
        "$link_snapshot"
)"


if [[ "$mode" != "600" ]]; then
    fail \
        "snapshot replacing symlink has mode $mode instead of 600"
fi


#
# Successful writes must not leave temporary .tmp.XXXXXX files behind.
#

if find \
    "$tmpdir" \
    -maxdepth 1 \
    -type f \
    -name '*.tmp.*' \
    -print \
    -quit |
    grep -q .; then

    fail \
        "temporary snapshot file was left behind"
fi


#
# Failure before publication must not create a partial destination.
#

if "$NSDIFF" \
    --capture \
    "$missing_parent_snapshot" \
    "$$" \
    >/dev/null \
    2>&1; then

    missing_parent_rc=0

else

    missing_parent_rc=$?
fi


if (( missing_parent_rc != 2 )); then
    fail \
        "capture into missing directory returned $missing_parent_rc instead of 2"
fi


if [[ -e "$missing_parent_snapshot" ]]; then
    fail \
        "failed capture left a destination file behind"
fi


if find \
    "$tmpdir" \
    -type f \
    -name '*.tmp.*' \
    -print \
    -quit |
    grep -q .; then

    fail \
        "failed capture left a temporary file behind"
fi


trap - EXIT

cleanup


echo "snapshot-atomic tests passed"

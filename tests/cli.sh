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
    echo "cli test failed: $*" >&2
    exit 1
}


child_pid=""
ready_file=""


cleanup()
{
    local pid="${child_pid:-}"
    local file="${ready_file:-}"

    if [[ -n "$pid" ]]; then
        kill "$pid" \
            2>/dev/null || true

        wait "$pid" \
            2>/dev/null || true
    fi

    if [[ -n "$file" ]]; then
        rm -f \
            "$file"
    fi

    child_pid=""
    ready_file=""
}


trap cleanup EXIT


#
# --version
#

version_output="$(
    "$NSDIFF" \
        --version
)"


grep -Eq \
    '^nsdiff [0-9]+\.[0-9]+\.[0-9]+$' \
    <<<"$version_output" \
    || fail \
        "--version output is invalid"


#
# --help
#

help_output="$(
    "$NSDIFF" \
        --help
)"


for option in \
    '--json' \
    '--only-differences' \
    '--explain' \
    '--summary' \
    '--quiet'
do

    grep -Fq \
        -- "$option" \
        <<<"$help_output" \
        || fail \
            "--help does not document $option"
done


#
# Same-process compact comparison.
#

same_output=""

if same_output="$(
    "$NSDIFF" \
        --only-differences \
        "$$" \
        "$$"
)"; then

    same_rc=0

else

    same_rc=$?
fi


if (( same_rc != 0 )); then
    fail \
        "same-process compact comparison returned $same_rc"
fi


grep -Eq \
    '^[[:space:]]+0 differences found$' \
    <<<"$same_output" \
    || fail \
        "same-process compact output contains differences"


#
# Same-process summary.
#

summary_output=""

if summary_output="$(
    "$NSDIFF" \
        --summary \
        "$$" \
        "$$"
)"; then

    summary_rc=0

else

    summary_rc=$?
fi


if (( summary_rc != 0 )); then
    fail \
        "same-process summary returned $summary_rc"
fi


grep -Fq \
    'Summary by domain' \
    <<<"$summary_output" \
    || fail \
        "summary heading is missing"


for section in \
    namespaces \
    credentials \
    limits \
    cgroup \
    network \
    mounts \
    environment \
    security
do

    grep -Eq \
        "^[[:space:]]+$section[[:space:]]" \
        <<<"$summary_output" \
        || fail \
            "summary section $section is missing"
done


grep -Eq \
    '^[[:space:]]+0 differences found$' \
    <<<"$summary_output" \
    || fail \
        "same-process summary contains differences"


#
# Same-process quiet.
#

quiet_output=""

if quiet_output="$(
    "$NSDIFF" \
        --quiet \
        "$$" \
        "$$"
)"; then

    quiet_rc=0

else

    quiet_rc=$?
fi


if (( quiet_rc != 0 )); then
    fail \
        "same-process quiet comparison returned $quiet_rc"
fi


if [[ -n "$quiet_output" ]]; then
    fail \
        "--quiet produced stdout for same process"
fi


#
# Create a process with a known environment difference.
#

ready_file="$(
    mktemp \
        /tmp/nsdiff-cli-ready.XXXXXX
)"

rm -f \
    "$ready_file"


env \
    LANG=nsdiff_CLI_TEST \
    sh -c '
        ready_file="$1"

        printf "ready\n" > "$ready_file"

        exec sleep 10
    ' \
    sh \
    "$ready_file" &

child_pid=$!


ready=0

for _ in {1..200}; do

    if [[ -f "$ready_file" ]]; then

        ready=1

        break
    fi

    if ! kill -0 \
        "$child_pid" \
        2>/dev/null; then

        break
    fi

    sleep 0.01
done


if (( ready != 1 )); then
    fail \
        "environment child did not become ready"
fi


#
# --only-differences
#

diff_output=""

if diff_output="$(
    "$NSDIFF" \
        --only-differences \
        "$$" \
        "$child_pid"
)"; then

    diff_rc=0

else

    diff_rc=$?
fi


if (( diff_rc != 1 )); then
    fail \
        "different-process compact comparison returned $diff_rc instead of 1"
fi


grep -Fq \
    'environment.LANG' \
    <<<"$diff_output" \
    || fail \
        "compact output did not contain environment.LANG"


#
# --explain
#

explain_output=""

if explain_output="$(
    "$NSDIFF" \
        --explain \
        "$$" \
        "$child_pid"
)"; then

    explain_rc=0

else

    explain_rc=$?
fi


if (( explain_rc != 1 )); then
    fail \
        "--explain returned $explain_rc instead of 1"
fi


grep -Fq \
    'why:' \
    <<<"$explain_output" \
    || fail \
        "--explain did not emit explanations"


#
# Different-process summary.
#

diff_summary=""

if diff_summary="$(
    "$NSDIFF" \
        --summary \
        "$$" \
        "$child_pid"
)"; then

    diff_summary_rc=0

else

    diff_summary_rc=$?
fi


if (( diff_summary_rc != 1 )); then
    fail \
        "different-process summary returned $diff_summary_rc instead of 1"
fi


grep -Eq \
    '^[[:space:]]+environment[[:space:]]+.*[1-9][0-9]* different' \
    <<<"$diff_summary" \
    || fail \
        "environment summary did not report a difference"


#
# Different-process quiet mode.
#

different_quiet_output=""

if different_quiet_output="$(
    "$NSDIFF" \
        --quiet \
        "$$" \
        "$child_pid"
)"; then

    different_quiet_rc=0

else

    different_quiet_rc=$?
fi


if (( different_quiet_rc != 1 )); then
    fail \
        "different-process quiet comparison returned $different_quiet_rc instead of 1"
fi


if [[ -n "$different_quiet_output" ]]; then
    fail \
        "--quiet produced stdout for different processes"
fi


cleanup


#
# Conflicting output modes.
#

conflict_rc=0

if "$NSDIFF" \
    --json \
    --summary \
    "$$" \
    "$$" \
    >/dev/null \
    2>&1; then

    conflict_rc=0

else

    conflict_rc=$?
fi


if (( conflict_rc != 2 )); then
    fail \
        "--json --summary returned $conflict_rc instead of 2"
fi


conflict_rc=0

if "$NSDIFF" \
    --quiet \
    --explain \
    "$$" \
    "$$" \
    >/dev/null \
    2>&1; then

    conflict_rc=0

else

    conflict_rc=$?
fi


if (( conflict_rc != 2 )); then
    fail \
        "--quiet --explain returned $conflict_rc instead of 2"
fi


#
# Unknown option.
#

unknown_rc=0

if "$NSDIFF" \
    --definitely-not-an-option \
    "$$" \
    "$$" \
    >/dev/null \
    2>&1; then

    unknown_rc=0

else

    unknown_rc=$?
fi


if (( unknown_rc != 2 )); then
    fail \
        "unknown option returned $unknown_rc instead of 2"
fi


trap - EXIT

echo "cli tests passed"

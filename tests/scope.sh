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
    echo "scope test failed: $*" >&2
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
# Same process in one scope.
#

if "$NSDIFF" \
    --section network \
    --quiet \
    "$$" \
    "$$"; then

    same_rc=0

else

    same_rc=$?
fi


if (( same_rc != 0 )); then
    fail \
        "same-process network scope returned $same_rc"
fi


#
# Create only a controlled environment difference.
#

ready_file="$(
    mktemp \
        /tmp/nsdiff-scope-ready.XXXXXX
)"

rm -f \
    "$ready_file"


env \
    LANG=nsdiff_SCOPE_TEST \
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
# Full comparison must differ.
#

if "$NSDIFF" \
    --quiet \
    "$$" \
    "$child_pid"; then

    full_rc=0

else

    full_rc=$?
fi


if (( full_rc != 1 )); then
    fail \
        "full comparison returned $full_rc instead of 1"
fi


#
# Network scope should ignore the environment difference.
#

if "$NSDIFF" \
    --section network \
    --quiet \
    "$$" \
    "$child_pid"; then

    network_rc=0

else

    network_rc=$?
fi


if (( network_rc != 0 )); then
    fail \
        "network scope returned $network_rc instead of 0"
fi


#
# Environment scope must detect it.
#

if "$NSDIFF" \
    --section environment \
    --quiet \
    "$$" \
    "$child_pid"; then

    environment_rc=0

else

    environment_rc=$?
fi


if (( environment_rc != 1 )); then
    fail \
        "environment scope returned $environment_rc instead of 1"
fi


#
# Compact scoped output.
#

environment_output=""

if environment_output="$(
    "$NSDIFF" \
        --section environment \
        --only-differences \
        "$$" \
        "$child_pid"
)"; then

    compact_rc=0

else

    compact_rc=$?
fi


if (( compact_rc != 1 )); then
    fail \
        "environment compact scope returned $compact_rc instead of 1"
fi


grep -Fq \
    'environment.LANG' \
    <<<"$environment_output" \
    || fail \
        "environment scope did not show environment.LANG"


if grep -Fq \
    'network.interfaces' \
    <<<"$environment_output"; then

    fail \
        "environment scope leaked network fields"
fi


#
# Multiple scopes.
#

if "$NSDIFF" \
    --section network \
    --section environment \
    --quiet \
    "$$" \
    "$child_pid"; then

    multiple_rc=0

else

    multiple_rc=$?
fi


if (( multiple_rc != 1 )); then
    fail \
        "multiple-section comparison returned $multiple_rc instead of 1"
fi


#
# Scoped summary contains only selected sections.
#

summary_output=""

if summary_output="$(
    "$NSDIFF" \
        --section network \
        --section environment \
        --summary \
        "$$" \
        "$child_pid"
)"; then

    summary_rc=0

else

    summary_rc=$?
fi


if (( summary_rc != 1 )); then
    fail \
        "scoped summary returned $summary_rc instead of 1"
fi


grep -Eq \
    '^[[:space:]]+network[[:space:]]' \
    <<<"$summary_output" \
    || fail \
        "network section missing from scoped summary"


grep -Eq \
    '^[[:space:]]+environment[[:space:]]' \
    <<<"$summary_output" \
    || fail \
        "environment section missing from scoped summary"


if grep -Eq \
    '^[[:space:]]+security[[:space:]]' \
    <<<"$summary_output"; then

    fail \
        "unselected security section appeared in scoped summary"
fi


#
# --section all must preserve the full result.
#

if "$NSDIFF" \
    --section all \
    --quiet \
    "$$" \
    "$child_pid"; then

    all_rc=0

else

    all_rc=$?
fi


if (( all_rc != full_rc )); then
    fail \
        "--section all returned $all_rc while full comparison returned $full_rc"
fi


cleanup


#
# Unknown section.
#

if "$NSDIFF" \
    --section potato \
    "$$" \
    "$$" \
    >/dev/null \
    2>&1; then

    invalid_rc=0

else

    invalid_rc=$?
fi


if (( invalid_rc != 2 )); then
    fail \
        "unknown section returned $invalid_rc instead of 2"
fi


#
# JSON scope is deliberately unsupported in schema v1.
#

if "$NSDIFF" \
    --json \
    --section network \
    "$$" \
    "$$" \
    >/dev/null \
    2>&1; then

    json_scope_rc=0

else

    json_scope_rc=$?
fi


if (( json_scope_rc != 2 )); then
    fail \
        "--json --section returned $json_scope_rc instead of 2"
fi


trap - EXIT

echo "scope tests passed"

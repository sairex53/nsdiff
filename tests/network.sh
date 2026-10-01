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
    echo "network test failed: $*" >&2
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
# Same-process text comparison.
#

same_output=""

if same_output="$(
    "$NSDIFF" \
        "$$" \
        "$$"
)"; then

    same_rc=0

else

    same_rc=$?
fi


if (( same_rc != 0 )); then

    fail \
        "same-process comparison returned $same_rc instead of 0"
fi


grep -Fq \
    "Network" \
    <<<"$same_output" \
    || fail \
        "network section is missing"


grep -Eq \
    'interfaces[[:space:]]+same' \
    <<<"$same_output" \
    || fail \
        "same interface set was not detected"


#
# Same-process JSON comparison.
#

same_json=""

if same_json="$(
    "$NSDIFF" \
        --json \
        "$$" \
        "$$"
)"; then

    same_json_rc=0

else

    same_json_rc=$?
fi


if (( same_json_rc != 0 )); then

    fail \
        "same-process JSON comparison returned $same_json_rc instead of 0"
fi


python3 -c '
import json
import sys

data = json.load(sys.stdin)

fields = {
    field["path"]: field
    for field in data["fields"]
}

required = [
    "network.interfaces",
    "network.ipv4_default_routes",
    "network.ipv6_addresses",
    "network.ipv6_default_routes",
]

for name in required:
    assert name in fields

assert fields["network.interfaces"]["state"] == "same"
' <<<"$same_json" \
    || fail \
        "same-process network JSON is invalid"


#
# Check whether unprivileged user + net namespaces
# are supported on this system.
#

if ! unshare \
    --user \
    --map-root-user \
    --net \
    true \
    2>/dev/null; then

    echo \
        "network tests skipped: unprivileged network namespaces unavailable"

    trap - EXIT

    exit 0
fi


#
# Create a process in a genuinely different
# user + network namespace.
#
# The marker is created by the command executed
# AFTER unshare has completed.
#

ready_file="$(
    mktemp \
        /tmp/nsdiff-network-ready.XXXXXX
)"

rm -f \
    "$ready_file"


unshare \
    --user \
    --map-root-user \
    --net \
    sh -c '
        ready_file="$1"

        printf "ready\n" \
            > "$ready_file"

        exec sleep 10
    ' \
    sh \
    "$ready_file" &

child_pid=$!


#
# Wait until the program executed inside the
# new namespaces has created its marker.
#

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
        "network namespace child did not become ready"
fi


#
# Do not merely trust the marker:
# explicitly verify that the network namespace
# inode is different before running nsdiff.
#

host_net_ns="$(
    readlink \
        "/proc/$$/ns/net"
)"

child_net_ns="$(
    readlink \
        "/proc/$child_pid/ns/net"
)"


if [[ "$host_net_ns" == "$child_net_ns" ]]; then

    fail \
        "child remained in the host network namespace"
fi


#
# The user namespace should also differ because
# --map-root-user implies a new user namespace.
#

host_user_ns="$(
    readlink \
        "/proc/$$/ns/user"
)"

child_user_ns="$(
    readlink \
        "/proc/$child_pid/ns/user"
)"


if [[ "$host_user_ns" == "$child_user_ns" ]]; then

    fail \
        "child remained in the host user namespace"
fi


#
# Text comparison.
#

diff_output=""

if diff_output="$(
    "$NSDIFF" \
        "$$" \
        "$child_pid"
)"; then

    diff_rc=0

else

    diff_rc=$?
fi


if (( diff_rc != 1 )); then

    printf '%s\n' \
        "$diff_output" \
        >&2

    fail \
        "different network namespace returned $diff_rc instead of 1"
fi


grep -Eq \
    'net[[:space:]]+different' \
    <<<"$diff_output" \
    || fail \
        "network namespace difference was not detected"


#
# A fresh network namespace normally contains
# only loopback, while the host usually contains
# additional interfaces.
#
# Only require the semantic interface difference
# when the host actually has more than one interface.
#

host_interface_count="$(
    awk -F: \
        'NR > 2 { name=$1; gsub(/[[:space:]]/, "", name); if (name != "") count++ } END { print count + 0 }' \
        "/proc/$$/net/dev"
)"


if (( host_interface_count > 1 )); then

    grep -Eq \
        'interfaces[[:space:]]+different' \
        <<<"$diff_output" \
        || fail \
            "network interface difference was not detected"
fi


#
# On a normal host with an IPv4 default route,
# the fresh network namespace should not have it.
#

host_default_routes="$(
    awk \
        'NR > 1 && $2 == "00000000" && $8 == "00000000" { count++ } END { print count + 0 }' \
        "/proc/$$/net/route"
)"


if (( host_default_routes > 0 )); then

    grep -Eq \
        'IPv4 default routes[[:space:]]+different' \
        <<<"$diff_output" \
        || fail \
            "IPv4 default-route difference was not detected"
fi


#
# JSON comparison.
#

diff_json=""

if diff_json="$(
    "$NSDIFF" \
        --json \
        "$$" \
        "$child_pid"
)"; then

    json_rc=0

else

    json_rc=$?
fi


if (( json_rc != 1 )); then

    fail \
        "JSON network comparison returned $json_rc instead of 1"
fi


python3 -c '
import json
import sys

data = json.load(sys.stdin)

assert data["summary"]["differences"] > 0

fields = {
    field["path"]: field
    for field in data["fields"]
}

interfaces = fields["network.interfaces"]

assert interfaces["status_a"] == "ok"
assert interfaces["status_b"] == "ok"

assert isinstance(
    interfaces["a"],
    list
)

assert isinstance(
    interfaces["b"],
    list
)
' <<<"$diff_json" \
    || fail \
        "different-network JSON is invalid"


cleanup

trap - EXIT

echo "network tests passed"

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
    echo "integration test failed: $*" >&2
    exit 1
}


if [[ ! -x "$NSDIFF" ]]; then
    fail "nsdiff executable not found: $NSDIFF"
fi


declare -a CHILD_PIDS=()


register_child()
{
    local pid="$1"

    CHILD_PIDS+=(
        "$pid"
    )
}


stop_child()
{
    local pid="$1"

    kill "$pid" \
        2>/dev/null || true

    wait "$pid" \
        2>/dev/null || true
}


cleanup()
{
    local pid

    for pid in "${CHILD_PIDS[@]}"; do

        kill "$pid" \
            2>/dev/null || true

        wait "$pid" \
            2>/dev/null || true
    done
}


trap cleanup EXIT


NSDIFF_OUTPUT=""
NSDIFF_RC=0


run_nsdiff()
{
    local pid_a="$1"
    local pid_b="$2"

    NSDIFF_OUTPUT=""
    NSDIFF_RC=0

    if NSDIFF_OUTPUT="$(
        "$NSDIFF" \
            "$pid_a" \
            "$pid_b" \
            2>&1
    )"; then

        NSDIFF_RC=0

    else

        NSDIFF_RC=$?
    fi
}


wait_for_proc_file()
{
    local pid="$1"
    local file="$2"

    local i

    for i in {1..100}; do

        if [[ -r "/proc/$pid/$file" ]]; then
            return 0
        fi

        if ! kill -0 "$pid" \
            2>/dev/null; then

            return 1
        fi

        sleep 0.01
    done

    return 1
}


#
# Same-process comparison.
#

run_nsdiff \
    "$$" \
    "$$"

if (( NSDIFF_RC != 0 )); then
    fail \
        "same process must return exit code 0, got $NSDIFF_RC"
fi


same_output="$NSDIFF_OUTPUT"


grep -Fq \
    "Namespaces" \
    <<<"$same_output" \
    || fail "namespace section is missing"


grep -Fq \
    "Resource limits" \
    <<<"$same_output" \
    || fail "resource limit section is missing"


grep -Fq \
    "Cgroup v2" \
    <<<"$same_output" \
    || fail "cgroup section is missing"


grep -Fq \
    "Mounts" \
    <<<"$same_output" \
    || fail "mount section is missing"


grep -Fq \
    "Shared memory" \
    <<<"$same_output" \
    || fail "shared memory section is missing"


grep -Fq \
    "Environment (exec-time)" \
    <<<"$same_output" \
    || fail "environment section is missing"


grep -Fq \
    "Capabilities" \
    <<<"$same_output" \
    || fail "capability section is missing"


grep -Fq \
    "Security" \
    <<<"$same_output" \
    || fail "security section is missing"


grep -Eq \
    'PATH[[:space:]]+same' \
    <<<"$same_output" \
    || fail "PATH environment was not collected"


grep -Eq \
    'Effective[[:space:]]+same' \
    <<<"$same_output" \
    || fail "effective capabilities were not collected"


grep -Eq \
    'Bounding[[:space:]]+same' \
    <<<"$same_output" \
    || fail "bounding capabilities were not collected"


grep -Eq \
    '/dev/shm size[[:space:]]+same' \
    <<<"$same_output" \
    || fail "/dev/shm size was not collected"


grep -Fq \
    "0 differences found" \
    <<<"$same_output" \
    || fail "same process unexpectedly contains differences"


#
# Invalid PID must be a fatal comparison error.
#

run_nsdiff \
    "$$" \
    999999999

if (( NSDIFF_RC != 2 )); then

    fail \
        "nonexistent process must return exit code 2, got $NSDIFF_RC"
fi


#
# Resource-limit difference.
#

bash -c '
    ulimit -S -s 1024
    exec sleep 10
' &

limit_child_pid=$!

register_child \
    "$limit_child_pid"


wait_for_proc_file \
    "$limit_child_pid" \
    limits \
    || fail "resource-limit child did not start"


run_nsdiff \
    "$$" \
    "$limit_child_pid"


if (( NSDIFF_RC != 1 )); then

    fail \
        "resource-limit difference must return exit code 1"
fi


grep -Eq \
    'RLIMIT_STACK[[:space:]]+different' \
    <<<"$NSDIFF_OUTPUT" \
    || fail "RLIMIT_STACK difference was not detected"


stop_child \
    "$limit_child_pid"


#
# Environment difference and secret redaction.
#

env \
    LANG=nsdiff_TEST_LOCALE \
    TMPDIR=/tmp/nsdiff-env-test \
    HTTP_PROXY='http://user:SUPER_SECRET_NSDIFF@127.0.0.1:12345' \
    sleep 10 &

env_child_pid=$!

register_child \
    "$env_child_pid"


wait_for_proc_file \
    "$env_child_pid" \
    environ \
    || fail "environment child did not start"


run_nsdiff \
    "$$" \
    "$env_child_pid"


if (( NSDIFF_RC != 1 )); then

    fail \
        "environment difference must return exit code 1"
fi


env_output="$NSDIFF_OUTPUT"


grep -Eq \
    'LANG[[:space:]]+different' \
    <<<"$env_output" \
    || fail "LANG environment difference was not detected"


grep -Eq \
    'TMPDIR[[:space:]]+different' \
    <<<"$env_output" \
    || fail "TMPDIR environment difference was not detected"


grep -Eq \
    'HTTP_PROXY[[:space:]]+different' \
    <<<"$env_output" \
    || fail "HTTP_PROXY environment difference was not detected"


if grep -Fq \
    'SUPER_SECRET_NSDIFF' \
    <<<"$env_output"; then

    fail \
        "redacted environment value leaked"
fi


stop_child \
    "$env_child_pid"


#
# User-namespace / capability difference.
#
# Skip this test on systems where unprivileged user
# namespaces are disabled.
#

if unshare \
    --user \
    --map-root-user \
    true \
    2>/dev/null; then

    unshare \
        --user \
        --map-root-user \
        sleep 10 &

    cap_child_pid=$!

    register_child \
        "$cap_child_pid"


    if wait_for_proc_file \
        "$cap_child_pid" \
        status; then

        run_nsdiff \
            "$$" \
            "$cap_child_pid"


        if (( NSDIFF_RC != 1 )); then

            fail \
                "user namespace difference must return exit code 1"
        fi


        grep -Fq \
            "different user namespaces" \
            <<<"$NSDIFF_OUTPUT" \
            || fail \
                "user namespace capability note is missing"


        grep -Eq \
            'Effective[[:space:]]+different' \
            <<<"$NSDIFF_OUTPUT" \
            || fail \
                "effective capability difference was not detected"
    fi


    stop_child \
        "$cap_child_pid"
fi


#
# Mount namespace and /dev/shm difference.
#
# First probe whether this host permits the operation.
#

if unshare \
    --user \
    --map-root-user \
    --mount \
    sh -c '
        mount \
            -t tmpfs \
            -o size=16M,mode=1777 \
            tmpfs \
            /dev/shm
    ' \
    2>/dev/null; then

    unshare \
        --user \
        --map-root-user \
        --mount \
        sh -c '
            mount \
                -t tmpfs \
                -o size=16M,mode=1777 \
                tmpfs \
                /dev/shm

            exec sleep 10
        ' &

    mount_child_pid=$!

    register_child \
        "$mount_child_pid"


    mount_ready=0

    for _ in {1..100}; do

        if grep -q \
            'size=16384k' \
            "/proc/$mount_child_pid/mountinfo" \
            2>/dev/null; then

            mount_ready=1
            break
        fi

        if ! kill -0 \
            "$mount_child_pid" \
            2>/dev/null; then

            break
        fi

        sleep 0.01
    done


    if (( mount_ready != 1 )); then

        fail \
            "private /dev/shm mount did not become ready"
    fi


    run_nsdiff \
        "$$" \
        "$mount_child_pid"


    if (( NSDIFF_RC != 1 )); then

        fail \
            "mount difference must return exit code 1"
    fi


    grep -Eq \
        '/dev/shm[[:space:]]+different' \
        <<<"$NSDIFF_OUTPUT" \
        || fail \
            "/dev/shm mount difference was not detected"


    grep -Eq \
        '/dev/shm size[[:space:]]+different' \
        <<<"$NSDIFF_OUTPUT" \
        || fail \
            "/dev/shm size difference was not detected"


    stop_child \
        "$mount_child_pid"
fi


echo "integration tests passed"

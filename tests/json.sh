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
    echo "json test failed: $*" >&2
    exit 1
}


child_pid=""
ready_file=""


cleanup()
{
    local pid="${child_pid:-}"

    if [[ -z "$pid" ]]; then
        return
    fi

    kill "$pid" \
        2>/dev/null || true

    wait "$pid" \
        2>/dev/null || true

    child_pid=""

    if [[ -n "${ready_file:-}" ]]; then
        rm -f \
            "$ready_file"
        ready_file=""
    fi
}


trap cleanup EXIT


#
# Same process:
# valid JSON and exit code 0.
#

same_json=""

if same_json="$(
    "$NSDIFF" \
        --json \
        "$$" \
        "$$"
)"; then

    same_rc=0

else

    same_rc=$?
fi


if (( same_rc != 0 )); then

    fail \
        "same process returned $same_rc instead of 0"
fi


python3 -c '
import json
import re
import sys

data = json.load(sys.stdin)

assert data["schema_version"] == 1

version = data["tool_version"]

assert isinstance(version, str)
assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)

assert data["summary"]["differences"] == 0
assert data["summary"]["comparable_fields"] > 0

assert isinstance(data["fields"], list)
assert len(data["fields"]) > 0
' <<<"$same_json" \
    || fail "same-process JSON is invalid"


#
# Different environment:
# valid JSON and exit code 1.
#

ready_file="$(
    mktemp \
        /tmp/nsdiff-json-ready.XXXXXX
)"

rm -f \
    "$ready_file"


env \
    LANG=nsdiff_JSON_TEST \
    TMPDIR=/tmp/nsdiff-json-test \
    HTTP_PROXY='http://user:SUPER_SECRET_JSON_NSDIFF@127.0.0.1:12345' \
    NSDIFF_TEST_READY="$ready_file" \
    bash -c '
        : >"$NSDIFF_TEST_READY"
        exec sleep 10
    ' &

child_pid=$!


json_child_ready=0

for _ in {1..200}; do

    if [[ -e "$ready_file" ]]; then
        json_child_ready=1
        break
    fi

    if ! kill -0 \
        "$child_pid" \
        2>/dev/null; then

        break
    fi

    sleep 0.01
done


if (( json_child_ready != 1 )); then
    fail \
        "environment child did not become ready"
fi


diff_json=""

if diff_json="$(
    "$NSDIFF" \
        --json \
        "$$" \
        "$child_pid"
)"; then

    diff_rc=0

else

    diff_rc=$?
fi


if (( diff_rc != 1 )); then

    fail \
        "different process returned $diff_rc instead of 1"
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

lang = fields["environment.LANG"]

assert lang["state"] == "different"
assert lang["b"] == "nsdiff_JSON_TEST"

proxy = fields["environment.HTTP_PROXY"]

assert proxy["redacted"] is True

if proxy["a"] is not None:
    assert proxy["a"] == "<redacted>"

if proxy["b"] is not None:
    assert proxy["b"] == "<redacted>"
' <<<"$diff_json" \
    || fail "different-process JSON is invalid"


if grep -Fq \
    'SUPER_SECRET_JSON_NSDIFF' \
    <<<"$diff_json"; then

    fail \
        "secret leaked into JSON output"
fi


cleanup


#
# Invalid PID:
# exit code 2.
#

invalid_output=""

if invalid_output="$(
    "$NSDIFF" \
        --json \
        "$$" \
        999999999 \
        2>/dev/null
)"; then

    invalid_rc=0

else

    invalid_rc=$?
fi


if (( invalid_rc != 2 )); then

    fail \
        "invalid PID returned $invalid_rc instead of 2"
fi


trap - EXIT

echo "json tests passed"

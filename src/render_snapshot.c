#include "nsdiff/json_writer.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "nsdiff/render_snapshot.h"


static int format_capture_time(
    const struct snapshot_metadata *metadata,
    char *buffer,
    size_t buffer_size
)
{
    time_t seconds;

    struct tm tm;

    size_t length;

    if (!metadata->have_provenance) {
        return -1;
    }

    seconds =
        (time_t)metadata->captured_sec;

    if ((int64_t)seconds !=
        metadata->captured_sec ||
        gmtime_r(
            &seconds,
            &tm
        ) == NULL) {

        if (snprintf(
                buffer,
                buffer_size,
                "%" PRId64 ".%09" PRId32 " UTC",
                metadata->captured_sec,
                metadata->captured_nsec
            ) >=
            (int)buffer_size) {

            return -1;
        }

        return 0;
    }

    length =
        strftime(
            buffer,
            buffer_size,
            "%Y-%m-%dT%H:%M:%S",
            &tm
        );

    if (length == 0U ||
        length >= buffer_size) {

        return -1;
    }

    if (snprintf(
            buffer + length,
            buffer_size - length,
            ".%09" PRId32 "Z",
            metadata->captured_nsec
        ) >=
        (int)(buffer_size - length)) {

        return -1;
    }

    return 0;
}



static void print_json_nullable_string(
    const char *text
)
{
    if (text == NULL) {

        fputs(
            "null",
            stdout
        );

        return;
    }

    nsdiff_json_write_string(text);
}



static void print_sha256_hex(
    const unsigned char digest[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ]
)
{
    size_t i;

    for (i = 0;
         i < NSDIFF_SNAPSHOT_SHA256_LEN;
         i++) {

        printf(
            "%02x",
            (unsigned int)digest[i]
        );
    }
}


static void print_snapshot_identity_value(
    const struct snapshot_identity *identity
)
{
    fputs(
        identity->portable ? "nsdiff:semantic-sha256:" : "nsdiff:sha256:",
        stdout
    );

    print_sha256_hex(
        identity->payload_sha256
    );
}


/* Portable verification validates syntax/schema; there is no stored digest. */
static void portable_report(const char *path, pid_t pid, unsigned long long starttime,
    const unsigned char *digest, const char *producer, int have_provenance,
    int64_t captured_sec, int32_t captured_nsec, const char *kernel, const char *machine, bool json)
{
    if (!json) {
        printf("Portable snapshot v1\n  file            %s\n  producer        %s\n"
               "  PID             %ld\n  starttime       %llu\n"
               "  validation      schema and semantic fields OK\n"
               "  stored digest   none\n  semantic id     nsdiff:semantic-sha256:",
               path, producer, (long)pid, starttime);
        print_sha256_hex(digest);
        putchar('\n');
        if (have_provenance)
            printf("  capture UTC     %" PRId64 ".%09" PRId32 "\n  kernel          %s\n  architecture    %s\n",
                   captured_sec, captured_nsec, kernel, machine);
        else fputs("  provenance      unavailable\n", stdout);
        return;
    }
    fputs("{\"schema_version\":1,\"document_type\":\"nsdiff-portable-report\","
          "\"format\":\"portable\",\"portable_schema\":1,\"valid\":true,\"file\":", stdout);
    nsdiff_json_write_string(path);
    fputs(",\"producer\":", stdout);
    nsdiff_json_write_string(producer);
    printf(",\"pid\":%ld,\"starttime_ticks\":\"%llu\",\"stored_digest\":null,"
           "\"semantic_id\":\"nsdiff:semantic-sha256:", (long)pid, starttime);
    print_sha256_hex(digest);
    fputs("\",\"provenance\":", stdout);
    if (have_provenance) {
        printf("{\"captured_sec\":\"%" PRId64 "\",\"captured_nsec\":%" PRId32 ",\"kernel\":", captured_sec, captured_nsec);
        nsdiff_json_write_string(kernel);
        fputs(",\"architecture\":", stdout);
        nsdiff_json_write_string(machine);
        putchar('}');
    } else fputs("null", stdout);
    fputs("}\n", stdout);
}

void render_snapshot_identity(
    const char *path,
    const struct snapshot_identity *identity
)
{
    (void)path;

    print_snapshot_identity_value(
        identity
    );

    putchar('\n');
}


void render_snapshot_identity_json(
    const char *path,
    const struct snapshot_identity *identity,
    const char *error
)
{
    if (identity != NULL && identity->portable) {
        fputs("{\"schema_version\":1,\"valid\":true,\"format\":\"portable\",\"scope\":\"semantic\",\"id\":\"", stdout);
        print_snapshot_identity_value(identity);
        fputs("\"}\n", stdout);
        return;
    }

    fputs(
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"file\": ",
        stdout
    );

    nsdiff_json_write_string(path);

    if (identity == NULL) {

        fputs(
            ",\n"
            "  \"valid\": false,\n"
            "  \"error\": ",
            stdout
        );

        print_json_nullable_string(
            error
        );

        fputs(
            "\n}\n",
            stdout
        );

        return;
    }

    fputs(
        ",\n"
        "  \"valid\": true,\n"
        "  \"id\": \"",
        stdout
    );

    print_snapshot_identity_value(
        identity
    );

    fputs(
        "\",\n"
        "  \"algorithm\": \"sha256\",\n"
        "  \"scope\": \"payload\",\n"
        "  \"digest\": \"",
        stdout
    );

    print_sha256_hex(
        identity->payload_sha256
    );

    printf(
        "\",\n"
        "  \"format_version\": %u,\n"
        "  \"producer\": ",
        identity->format_version
    );

    nsdiff_json_write_string(
        identity->tool_version
    );

    printf(
        ",\n"
        "  \"pid\": %ld,\n"
        "  \"starttime_ticks\": %llu\n"
        "}\n",
        (long)identity->pid,
        identity->starttime_ticks
    );
}


static int format_identity_capture_time(
    const struct snapshot_identity *identity,
    char *buffer,
    size_t buffer_size
)
{
    time_t seconds;

    struct tm tm;

    size_t length;

    if (!identity->have_provenance) {
        return -1;
    }

    seconds =
        (time_t)identity->captured_sec;

    if ((int64_t)seconds !=
            identity->captured_sec ||
        gmtime_r(
            &seconds,
            &tm
        ) == NULL) {

        if (snprintf(
                buffer,
                buffer_size,
                "%" PRId64 ".%09" PRId32 " UTC",
                identity->captured_sec,
                identity->captured_nsec
            ) >=
            (int)buffer_size) {

            return -1;
        }

        return 0;
    }

    length =
        strftime(
            buffer,
            buffer_size,
            "%Y-%m-%dT%H:%M:%S",
            &tm
        );

    if (length == 0U ||
        length >= buffer_size) {

        return -1;
    }

    if (snprintf(
            buffer + length,
            buffer_size - length,
            ".%09" PRId32 "Z",
            identity->captured_nsec
        ) >=
        (int)(buffer_size - length)) {

        return -1;
    }

    return 0;
}


void render_snapshot_manifest(
    const char *path,
    const struct snapshot_identity *identity
)
{
    if (identity->portable) {
        portable_report(path, identity->pid, identity->starttime_ticks, identity->payload_sha256, identity->tool_version,
            identity->have_provenance, identity->captured_sec, identity->captured_nsec, identity->kernel_release, identity->machine, false);
        return;
    }

    char capture_time[96];

    bool have_capture_time =
        format_identity_capture_time(
            identity,
            capture_time,
            sizeof(capture_time)
        ) == 0;

    printf(
        "Snapshot manifest\n"
        "  file            %s\n"
        "  id              ",
        path
    );

    print_snapshot_identity_value(
        identity
    );

    printf(
        "\n"
        "  format          %u\n"
        "  ABI             %u\n"
        "  producer        nsdiff %s\n"
        "  PID             %ld\n"
        "  starttime       %llu\n"
        "  payload bytes   %" PRIu64 "\n"
        "  FNV-1a          0x%016" PRIx64 " [ok]\n"
        "  computed sha256 ",
        identity->format_version,
        identity->abi_version,
        identity->tool_version,
        (long)identity->pid,
        identity->starttime_ticks,
        identity->snapshot_size,
        identity->payload_hash
    );

    print_sha256_hex(
        identity->payload_sha256
    );

    putchar('\n');

    if (identity->have_stored_sha256) {

        printf(
            "  stored sha256   "
        );

        print_sha256_hex(
            identity->stored_sha256
        );

        printf(
            " [%s]\n",
            identity->stored_sha256_valid
                ? "ok"
                : "invalid"
        );

    } else {

        printf(
            "  stored sha256   unavailable (legacy snapshot)\n"
        );
    }

    printf(
        "  captured        %s\n",
        have_capture_time
            ? capture_time
            : "unavailable (legacy snapshot)"
    );

    if (identity->have_provenance) {

        printf(
            "  kernel          %s\n"
            "  architecture    %s\n",
            identity->kernel_release,
            identity->machine
        );

    } else {

        printf(
            "  kernel          unavailable\n"
            "  architecture    unavailable\n"
        );
    }

    printf(
        "  result          valid\n"
    );
}


void render_snapshot_manifest_json(
    const char *path,
    const struct snapshot_identity *identity,
    const char *error
)
{
    if (identity != NULL && identity->portable) {
        portable_report(path, identity->pid, identity->starttime_ticks, identity->payload_sha256, identity->tool_version,
            identity->have_provenance, identity->captured_sec, identity->captured_nsec, identity->kernel_release, identity->machine, true);
        return;
    }

    char capture_time[96];

    bool have_capture_time = false;

    fputs(
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"document_type\": \"nsdiff-snapshot-manifest\",\n"
        "  \"file\": ",
        stdout
    );

    nsdiff_json_write_string(path);

    if (identity == NULL) {

        fputs(
            ",\n"
            "  \"valid\": false,\n"
            "  \"error\": ",
            stdout
        );

        print_json_nullable_string(
            error
        );

        fputs(
            "\n}\n",
            stdout
        );

        return;
    }

    if (identity->have_provenance) {

        have_capture_time =
            format_identity_capture_time(
                identity,
                capture_time,
                sizeof(capture_time)
            ) == 0;
    }

    fputs(
        ",\n"
        "  \"valid\": true,\n"
        "  \"identity\": {\n"
        "    \"id\": \"",
        stdout
    );

    print_snapshot_identity_value(
        identity
    );

    fputs(
        "\",\n"
        "    \"algorithm\": \"sha256\",\n"
        "    \"scope\": \"payload\",\n"
        "    \"digest\": \"",
        stdout
    );

    print_sha256_hex(
        identity->payload_sha256
    );

    fputs(
        "\"\n"
        "  },\n"
        "  \"native\": {\n",
        stdout
    );

    printf(
        "    \"format_version\": %u,\n"
        "    \"abi_version\": %u,\n"
        "    \"payload_bytes\": %" PRIu64 "\n"
        "  },\n"
        "  \"producer\": ",
        identity->format_version,
        identity->abi_version,
        identity->snapshot_size
    );

    nsdiff_json_write_string(
        identity->tool_version
    );

    printf(
        ",\n"
        "  \"process\": {\n"
        "    \"pid\": %ld,\n"
        "    \"starttime_ticks\": %llu\n"
        "  },\n"
        "  \"integrity\": {\n"
        "    \"verified\": true,\n"
        "    \"fnv1a64\": \"0x%016" PRIx64 "\",\n"
        "    \"computed_sha256\": \"",
        (long)identity->pid,
        identity->starttime_ticks,
        identity->payload_hash
    );

    print_sha256_hex(
        identity->payload_sha256
    );

    fputs(
        "\",\n"
        "    \"stored_sha256\": ",
        stdout
    );

    if (identity->have_stored_sha256) {

        putchar('"');

        print_sha256_hex(
            identity->stored_sha256
        );

        putchar('"');

    } else {

        fputs(
            "null",
            stdout
        );
    }

    printf(
        ",\n"
        "    \"stored_sha256_verified\": %s\n"
        "  },\n"
        "  \"provenance\": ",
        identity->have_stored_sha256
            ? (identity->stored_sha256_valid
                   ? "true"
                   : "false")
            : "null"
    );

    if (!identity->have_provenance) {

        fputs(
            "null\n",
            stdout
        );

    } else {

        fputs(
            "{\n"
            "    \"captured_at\": ",
            stdout
        );

        if (have_capture_time) {

            nsdiff_json_write_string(
                capture_time
            );

        } else {

            fputs(
                "null",
                stdout
            );
        }

        fputs(
            ",\n"
            "    \"kernel\": ",
            stdout
        );

        nsdiff_json_write_string(
            identity->kernel_release
        );

        fputs(
            ",\n"
            "    \"architecture\": ",
            stdout
        );

        nsdiff_json_write_string(
            identity->machine
        );

        fputs(
            "\n"
            "  }\n",
            stdout
        );
    }

    fputs(
        "}\n",
        stdout
    );
}


void render_snapshot_metadata(
    const char *path,
    const struct snapshot_metadata *metadata
)
{
    if (metadata->portable) {
        portable_report(path, metadata->pid, metadata->starttime_ticks, metadata->payload_sha256, metadata->tool_version,
            metadata->have_provenance, metadata->captured_sec, metadata->captured_nsec, metadata->kernel_release, metadata->machine, false);
        return;
    }

    char capture_time[96];

    bool have_capture_time =
        format_capture_time(
            metadata,
            capture_time,
            sizeof(capture_time)
        ) == 0;

    printf(
        "Snapshot\n"
        "  file            %s\n"
        "  format          %u\n"
        "  ABI             %u\n"
        "  producer        nsdiff %s\n"
        "  PID             %ld\n"
        "  starttime       %llu\n"
        "  payload bytes   %" PRIu64 "\n"
        "  checksum        %s\n"
        "  captured        %s\n",
        path,
        metadata->format_version,
        metadata->abi_version,
        metadata->tool_version,
        (long)metadata->pid,
        metadata->starttime_ticks,
        metadata->snapshot_size,
        metadata->checksum_valid
            ? "ok"
            : "invalid",
        have_capture_time
            ? capture_time
            : "unavailable (legacy snapshot)"
    );

    if (metadata->have_sha256) {

        printf(
            "  sha256          "
        );

        print_sha256_hex(
            metadata->payload_sha256
        );

        printf(
            " [%s]\n",
            metadata->sha256_valid
                ? "ok"
                : "invalid"
        );
    }

    if (metadata->have_provenance) {

        printf(
            "  kernel          %s\n"
            "  architecture    %s\n",
            metadata->kernel_release,
            metadata->machine
        );

    } else {

        printf(
            "  kernel          unavailable\n"
            "  architecture    unavailable\n"
        );
    }
}


void render_snapshot_metadata_json(
    const char *path,
    const struct snapshot_metadata *metadata,
    const char *error
)
{
    if (metadata != NULL && metadata->portable) {
        portable_report(path, metadata->pid, metadata->starttime_ticks, metadata->payload_sha256, metadata->tool_version,
            metadata->have_provenance, metadata->captured_sec, metadata->captured_nsec, metadata->kernel_release, metadata->machine, true);
        return;
    }

    char capture_time[96];

    bool have_capture_time = false;

    fputs(
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"valid\": ",
        stdout
    );

    fputs(
        metadata != NULL
            ? "true"
            : "false",
        stdout
    );

    fputs(
        ",\n"
        "  \"file\": ",
        stdout
    );

    nsdiff_json_write_string(path);

    if (metadata == NULL) {

        fputs(
            ",\n"
            "  \"error\": ",
            stdout
        );

        print_json_nullable_string(error);

        fputs(
            "\n}\n",
            stdout
        );

        return;
    }

    if (metadata->have_provenance) {

        have_capture_time =
            format_capture_time(
                metadata,
                capture_time,
                sizeof(capture_time)
            ) == 0;
    }

    printf(
        ",\n"
        "  \"format_version\": %u,\n"
        "  \"abi_version\": %u,\n"
        "  \"producer\": ",
        metadata->format_version,
        metadata->abi_version
    );

    nsdiff_json_write_string(
        metadata->tool_version
    );

    printf(
        ",\n"
        "  \"pid\": %ld,\n"
        "  \"starttime_ticks\": %llu,\n"
        "  \"payload_bytes\": %" PRIu64 ",\n"
        "  \"payload_hash\": \"0x%016" PRIx64 "\",\n"
        "  \"checksum\": \"%s\",\n"
        "  \"sha256\": ",
        (long)metadata->pid,
        metadata->starttime_ticks,
        metadata->snapshot_size,
        metadata->payload_hash,
        metadata->checksum_valid
            ? "ok"
            : "invalid"
    );

    if (metadata->have_sha256) {

        putchar('"');

        print_sha256_hex(
            metadata->payload_sha256
        );

        putchar('"');

    } else {

        fputs(
            "null",
            stdout
        );
    }

    fputs(
        ",\n"
        "  \"captured_at\": ",
        stdout
    );

    if (have_capture_time) {

        nsdiff_json_write_string(
            capture_time
        );

    } else {

        fputs(
            "null",
            stdout
        );
    }

    fputs(
        ",\n"
        "  \"kernel\": ",
        stdout
    );

    if (metadata->have_provenance) {

        nsdiff_json_write_string(
            metadata->kernel_release
        );

    } else {

        fputs(
            "null",
            stdout
        );
    }

    fputs(
        ",\n"
        "  \"architecture\": ",
        stdout
    );

    if (metadata->have_provenance) {

        nsdiff_json_write_string(
            metadata->machine
        );

    } else {

        fputs(
            "null",
            stdout
        );
    }

    fputs(
        "\n}\n",
        stdout
    );
}


void render_snapshot_verification_json(
    const char *path,
    bool valid,
    const char *error
)
{
    fputs(
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"valid\": ",
        stdout
    );

    fputs(
        valid
            ? "true"
            : "false",
        stdout
    );

    fputs(
        ",\n"
        "  \"file\": ",
        stdout
    );

    nsdiff_json_write_string(path);

    if (!valid) {

        fputs(
            ",\n"
            "  \"error\": ",
            stdout
        );

        print_json_nullable_string(error);
    }

    fputs(
        "\n}\n",
        stdout
    );
}

static const char *compat_yes_no(
    int value
)
{
    return value
        ? "yes"
        : "no";
}


static const char *compat_ok_bad(
    int value
)
{
    return value
        ? "ok"
        : "bad";
}


void render_snapshot_compatibility(
    const char *path,
    const struct snapshot_compat_report *report
)
{
    if (report->portable) { printf("Portable snapshot v1: %s\n", report->reason); return; }

    printf(
        "Snapshot compatibility\n"
        "  file            %s\n"
        "  magic           %s\n"
        "  format          %u [%s]\n"
        "  ABI             %u [%s]\n"
        "  endian marker   0x%08" PRIx32 " [%s]\n"
        "  payload bytes   %" PRIu64 " [%s]\n"
        "  provenance      %s\n"
        "  payload         %s\n",
        path,
        compat_ok_bad(report->magic_valid),
        report->format_version,
        report->format_supported
            ? "supported"
            : "unsupported",
        report->abi_version,
        report->abi_supported
            ? "supported"
            : "unsupported",
        report->endian_marker,
        report->endian_supported
            ? "supported"
            : "unsupported",
        report->snapshot_size,
        report->snapshot_size_supported
            ? "compatible"
            : "incompatible",
        compat_ok_bad(report->extension_valid),
        report->payload_complete
            ? "complete"
            : "incomplete"
    );

    if (report->checksum_checked) {

        printf(
            "  checksum        %s\n",
            compat_ok_bad(
                report->checksum_valid
            )
        );

    } else {

        printf(
            "  checksum        not checked\n"
        );
    }

    if (report->sha256_checked) {

        printf(
            "  sha256          %s\n",
            compat_ok_bad(
                report->sha256_valid
            )
        );

    } else {

        printf(
            "  sha256          not present\n"
        );
    }

    printf(
        "  trailing data   %s\n"
        "  result          %s\n"
        "  reason          %s\n",
        compat_yes_no(
            report->trailing_data
        ),
        report->compatible
            ? "compatible"
            : "incompatible",
        report->reason[0] != '\0'
            ? report->reason
            : "unknown"
    );
}


void render_snapshot_compatibility_json(
    const char *path,
    const struct snapshot_compat_report *report,
    const char *error
)
{
    if (report != NULL && report->portable) { printf("{\"schema_version\":1,\"format\":\"portable\",\"compatible\":%s}\n", report->compatible ? "true" : "false"); return; }

    fputs(
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"file\": ",
        stdout
    );

    nsdiff_json_write_string(path);

    if (report == NULL) {

        fputs(
            ",\n"
            "  \"compatible\": false,\n"
            "  \"error\": ",
            stdout
        );

        print_json_nullable_string(error);

        fputs(
            "\n}\n",
            stdout
        );

        return;
    }

    printf(
        ",\n"
        "  \"compatible\": %s,\n"
        "  \"header_read\": %s,\n"
        "  \"magic_valid\": %s,\n"
        "  \"format_version\": %u,\n"
        "  \"format_supported\": %s,\n"
        "  \"abi_version\": %u,\n"
        "  \"abi_supported\": %s,\n"
        "  \"endian_marker\": \"0x%08" PRIx32 "\",\n"
        "  \"endian_supported\": %s,\n"
        "  \"snapshot_size\": %" PRIu64 ",\n"
        "  \"snapshot_size_supported\": %s,\n"
        "  \"producer\": ",
        report->compatible ? "true" : "false",
        report->header_read ? "true" : "false",
        report->magic_valid ? "true" : "false",
        report->format_version,
        report->format_supported ? "true" : "false",
        report->abi_version,
        report->abi_supported ? "true" : "false",
        report->endian_marker,
        report->endian_supported ? "true" : "false",
        report->snapshot_size,
        report->snapshot_size_supported ? "true" : "false"
    );

    if (report->magic_valid) {

        nsdiff_json_write_string(
            report->tool_version
        );

    } else {

        fputs(
            "null",
            stdout
        );
    }

    printf(
        ",\n"
        "  \"extension_valid\": %s,\n"
        "  \"payload_complete\": %s,\n"
        "  \"checksum_checked\": %s,\n"
        "  \"checksum_valid\": %s,\n"
        "  \"sha256_checked\": %s,\n"
        "  \"sha256_valid\": %s,\n"
        "  \"trailing_data\": %s,\n"
        "  \"reason\": ",
        report->extension_valid ? "true" : "false",
        report->payload_complete ? "true" : "false",
        report->checksum_checked ? "true" : "false",
        report->checksum_valid ? "true" : "false",
        report->sha256_checked ? "true" : "false",
        report->sha256_valid ? "true" : "false",
        report->trailing_data ? "true" : "false"
    );

    nsdiff_json_write_string(
        report->reason[0] != '\0'
            ? report->reason
            : "unknown"
    );

    fputs(
        "\n}\n",
        stdout
    );
}

void render_snapshot_schema(void)
{
    printf(
        "Snapshot schema\n"
        "  native current          %u\n"
        "  native supported        %u-%u\n"
        "  ABI                     %u\n"
        "  endian marker           0x%08" PRIx32 "\n"
        "  payload bytes           %zu\n"
        "  payload checksum        FNV-1a 64\n"
        "  payload digest          SHA-256 (format 3+)\n"
        "  provenance              yes\n"
        "  stdin/stdout            yes\n"
        "  atomic file writes      yes\n"
        "  snapshot file mode      0600\n"
        "  diff JSON schema        1\n"
        "  metadata JSON schema    1\n"
        "  compat JSON schema      1\n"
        "  snapshot identity       SHA-256 payload\n"
        "  identity JSON schema    1\n"
        "  manifest JSON schema    1\n"
        "  portable snapshot       v1 (import/export, semantic SHA-256)\n",
        NSDIFF_SNAPSHOT_FORMAT_VERSION,
        NSDIFF_SNAPSHOT_MIN_FORMAT_VERSION,
        NSDIFF_SNAPSHOT_FORMAT_VERSION,
        NSDIFF_SNAPSHOT_ABI_VERSION,
        NSDIFF_SNAPSHOT_ENDIAN_MARKER,
        sizeof(struct process_snapshot)
    );
}


void render_snapshot_schema_json(void)
{
    printf(
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"native_snapshot\": {\n"
        "    \"current_format\": %u,\n"
        "    \"supported_formats\": [",
        NSDIFF_SNAPSHOT_FORMAT_VERSION
    );

    {
        uint32_t version;

        for (version =
                 NSDIFF_SNAPSHOT_MIN_FORMAT_VERSION;
             version <=
                 NSDIFF_SNAPSHOT_FORMAT_VERSION;
             version++) {

            if (version !=
                NSDIFF_SNAPSHOT_MIN_FORMAT_VERSION) {

                fputs(
                    ", ",
                    stdout
                );
            }

            printf(
                "%u",
                version
            );
        }
    }

    printf(
        "],\n"
        "    \"abi_version\": %u,\n"
        "    \"endian_marker\": \"0x%08" PRIx32 "\",\n"
        "    \"payload_bytes\": %zu,\n"
        "    \"payload_checksum\": \"fnv1a64\",\n"
        "    \"payload_digest\": \"sha256\",\n"
        "    \"payload_digest_since_format\": 3,\n"
        "    \"provenance\": true,\n"
        "    \"stdin_stdout\": true,\n"
        "    \"atomic_file_writes\": true,\n"
        "    \"file_mode\": \"0600\"\n"
        "  },\n"
        "  \"json\": {\n"
        "    \"diff_schema\": 1,\n"
        "    \"metadata_schema\": 1,\n"
        "    \"compatibility_schema\": 1,\n"
        "    \"manifest_schema\": 1\n"
        "  },\n"
        "  \"identity\": {\n"
        "    \"supported\": true,\n"
        "    \"schema_version\": 1,\n"
        "    \"algorithm\": \"sha256\",\n"
        "    \"scope\": \"payload\",\n"
        "    \"prefix\": \"nsdiff:sha256:\"\n"
        "  },\n"
        "  \"portable_snapshot\": {\n"
        "    \"supported\": true,\n"
        "    \"schema_version\": 1,\n"
        "    \"import\": true,\n"
        "    \"export\": true\n"
        "  }\n"
        "}\n",
        NSDIFF_SNAPSHOT_ABI_VERSION,
        NSDIFF_SNAPSHOT_ENDIAN_MARKER,
        sizeof(struct process_snapshot)
    );
}

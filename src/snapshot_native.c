#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "config.h"

#include "nsdiff/snapshot_io.h"
#include "nsdiff/snapshot_internal.h"
#include "nsdiff/sha256.h"


#define SNAPSHOT_MAGIC_SIZE 16U

#define SNAPSHOT_FORMAT_V1 1U
#define SNAPSHOT_FORMAT_V2 2U
#define SNAPSHOT_FORMAT_V3 3U

#define SNAPSHOT_DIGEST_SHA256 1U

#define SNAPSHOT_PROBE_MAX_PAYLOAD \
    UINT64_C(67108864)

#define SNAPSHOT_PROBE_MAX_EXTENSION \
    UINT32_C(1048576)


static const unsigned char snapshot_magic[
    SNAPSHOT_MAGIC_SIZE
] = {
    'N', 'S', 'D', 'I', 'F', 'F',
    'S', 'N', 'A', 'P',
    0, 0, 0, 0, 0, 0
};


struct snapshot_file_header {
    unsigned char magic[
        SNAPSHOT_MAGIC_SIZE
    ];

    uint32_t format_version;
    uint32_t abi_version;

    uint32_t endian_marker;
    uint32_t reserved;

    uint64_t snapshot_size;
    uint64_t payload_hash;

    char tool_version[
        NSDIFF_SNAPSHOT_VERSION_LEN
    ];
};


struct snapshot_v2_extension {
    uint32_t extension_size;
    uint32_t reserved;

    int64_t captured_sec;
    int32_t captured_nsec;
    uint32_t reserved2;

    char kernel_release[
        NSDIFF_SNAPSHOT_KERNEL_LEN
    ];

    char machine[
        NSDIFF_SNAPSHOT_MACHINE_LEN
    ];
};


struct snapshot_v3_extension {
    uint32_t extension_size;
    uint32_t reserved;

    int64_t captured_sec;
    int32_t captured_nsec;
    uint32_t reserved2;

    char kernel_release[
        NSDIFF_SNAPSHOT_KERNEL_LEN
    ];

    char machine[
        NSDIFF_SNAPSHOT_MACHINE_LEN
    ];

    uint32_t digest_algorithm;
    uint32_t digest_size;

    unsigned char payload_sha256[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ];
};



static int sha256_equal(
    const unsigned char a[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ],
    const unsigned char b[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ]
)
{
    unsigned int difference =
        0U;

    size_t i;

    for (i = 0;
         i < NSDIFF_SNAPSHOT_SHA256_LEN;
         i++) {

        difference |=
            (unsigned int)(
                a[i] ^
                b[i]
            );
    }

    return difference == 0U;
}


static uint64_t fnv1a64_update(
    uint64_t hash,
    const void *data,
    size_t size
)
{
    const unsigned char *bytes =
        data;

    size_t i;

    for (i = 0;
         i < size;
         i++) {

        hash ^=
            (uint64_t)bytes[i];

        hash *=
            UINT64_C(1099511628211);
    }

    return hash;
}


static uint64_t fnv1a64(
    const void *data,
    size_t size
)
{
    return fnv1a64_update(
        UINT64_C(14695981039346656037),
        data,
        size
    );
}


static void reset_snapshot(
    struct process_snapshot *snapshot
)
{
    memset(
        snapshot,
        0,
        sizeof(*snapshot)
    );

    snapshot->pidfd = -1;
}


static int read_exact(
    FILE *stream,
    void *data,
    size_t size
)
{
    return fread(
        data,
        1,
        size,
        stream
    ) == size
        ? 0
        : -1;
}


static int validate_header(
    const struct snapshot_file_header *header,
    char *error_buf,
    size_t error_buf_size
)
{
    if (memcmp(
            header->magic,
            snapshot_magic,
            sizeof(snapshot_magic)
        ) != 0) {

        snprintf(
            error_buf,
            error_buf_size,
            "not an nsdiff snapshot"
        );

        return -1;
    }

    if (memchr(header->tool_version, 0, sizeof(header->tool_version)) == NULL ||
        header->reserved != 0) {
        snprintf(error_buf, error_buf_size, "invalid native header metadata");
        return -1;
    }
    if (header->format_version !=
            SNAPSHOT_FORMAT_V1 &&
        header->format_version !=
            SNAPSHOT_FORMAT_V2 &&
        header->format_version !=
            SNAPSHOT_FORMAT_V3) {

        snprintf(
            error_buf,
            error_buf_size,
            "unsupported snapshot format version %u",
            header->format_version
        );

        return -1;
    }

    if (header->abi_version !=
        NSDIFF_SNAPSHOT_ABI_VERSION) {

        snprintf(
            error_buf,
            error_buf_size,
            "unsupported snapshot ABI version %u",
            header->abi_version
        );

        return -1;
    }

    if (header->endian_marker !=
        NSDIFF_SNAPSHOT_ENDIAN_MARKER) {

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot byte order is incompatible"
        );

        return -1;
    }

    if (header->snapshot_size !=
        (uint64_t)sizeof(struct process_snapshot)) {

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot structure size is incompatible"
        );

        return -1;
    }

    return 0;
}


static int read_snapshot_file(
    FILE *stream,
    struct snapshot_file_header *header,
    struct snapshot_v3_extension *extension,
    struct process_snapshot *snapshot,
    char *error_buf,
    size_t error_buf_size
)
{

    int close_stream = 0;
    int extra;

    memset(
        header,
        0,
        sizeof(*header)
    );

    memset(
        extension,
        0,
        sizeof(*extension)
    );

    reset_snapshot(snapshot);

    if (read_exact(
            stream,
            header,
            sizeof(*header)
        ) != 0) {

        if (close_stream) {
            fclose(stream);
        }

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot header is truncated"
        );

        return -1;
    }

    if (validate_header(
            header,
            error_buf,
            error_buf_size
        ) != 0) {

        if (close_stream) {
            fclose(stream);
        }

        return -1;
    }

    if (header->format_version ==
            SNAPSHOT_FORMAT_V2 ||
        header->format_version ==
            SNAPSHOT_FORMAT_V3) {

        size_t extension_size =
            header->format_version ==
                SNAPSHOT_FORMAT_V2
                    ? sizeof(
                          struct snapshot_v2_extension
                      )
                    : sizeof(
                          struct snapshot_v3_extension
                      );

        if (read_exact(
                stream,
                extension,
                extension_size
            ) != 0) {

            if (close_stream) {
                fclose(stream);
            }

            snprintf(
                error_buf,
                error_buf_size,
                "snapshot provenance is truncated"
            );

            return -1;
        }

        if (extension->extension_size !=
            (uint32_t)extension_size) {

            if (close_stream) {
                fclose(stream);
            }

            snprintf(
                error_buf,
                error_buf_size,
                "snapshot provenance size is incompatible"
            );

            return -1;
        }

        if (extension->captured_nsec < 0 ||
            extension->captured_nsec >=
                1000000000) {

            if (close_stream) {
                fclose(stream);
            }

            snprintf(
                error_buf,
                error_buf_size,
                "snapshot contains invalid capture time"
            );

            return -1;
        }

        if (memchr(extension->kernel_release, 0, sizeof(extension->kernel_release)) == NULL ||
            memchr(extension->machine, 0, sizeof(extension->machine)) == NULL ||
            extension->reserved != 0 || extension->reserved2 != 0) {
            snprintf(error_buf, error_buf_size, "invalid native provenance");
            return -1;
        }

        if (header->format_version ==
            SNAPSHOT_FORMAT_V3) {

            if (extension->digest_algorithm !=
                    SNAPSHOT_DIGEST_SHA256 ||
                extension->digest_size !=
                    NSDIFF_SNAPSHOT_SHA256_LEN) {

                if (close_stream) {
                    fclose(stream);
                }

                snprintf(
                    error_buf,
                    error_buf_size,
                    "snapshot payload digest metadata is incompatible"
                );

                return -1;
            }
        }
    }

    if (read_exact(
            stream,
            snapshot,
            sizeof(*snapshot)
        ) != 0) {

        if (close_stream) {
            fclose(stream);
        }

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot payload is truncated"
        );

        return -1;
    }

    extra =
        fgetc(stream);

    if (extra != EOF) {

        if (close_stream) {
            fclose(stream);
        }

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot contains unexpected trailing data"
        );

        return -1;
    }

    if (ferror(stream)) {

        if (close_stream) {
            fclose(stream);
        }

        snprintf(
            error_buf,
            error_buf_size,
            "cannot finish reading snapshot"
        );

        return -1;
    }

    if (close_stream &&
        fclose(stream) != 0) {

        snprintf(
            error_buf,
            error_buf_size,
            "cannot close snapshot: %s",
            strerror(errno)
        );

        return -1;
    }

    return 0;
}


static int collect_v3_extension(
    struct snapshot_v3_extension *extension,
    char *error_buf,
    size_t error_buf_size
)
{
    struct timespec now;

    struct utsname uts;

    memset(
        extension,
        0,
        sizeof(*extension)
    );

    extension->extension_size =
        (uint32_t)sizeof(*extension);

    if (clock_gettime(
            CLOCK_REALTIME,
            &now
        ) != 0) {

        snprintf(
            error_buf,
            error_buf_size,
            "cannot read capture time: %s",
            strerror(errno)
        );

        return -1;
    }

    if (uname(&uts) != 0) {

        snprintf(
            error_buf,
            error_buf_size,
            "cannot read system provenance: %s",
            strerror(errno)
        );

        return -1;
    }

    extension->captured_sec =
        (int64_t)now.tv_sec;

    extension->captured_nsec =
        (int32_t)now.tv_nsec;

    if (snprintf(
            extension->kernel_release,
            sizeof(extension->kernel_release),
            "%s",
            uts.release
        ) >=
        (int)sizeof(extension->kernel_release)) {

        snprintf(
            error_buf,
            error_buf_size,
            "kernel release is too long for snapshot metadata"
        );

        return -1;
    }

    if (snprintf(
            extension->machine,
            sizeof(extension->machine),
            "%s",
            uts.machine
        ) >=
        (int)sizeof(extension->machine)) {

        snprintf(
            error_buf,
            error_buf_size,
            "machine architecture is too long for snapshot metadata"
        );

        return -1;
    }

    return 0;
}


static uint32_t swap_u32(
    uint32_t value
)
{
    return ((value & UINT32_C(0x000000ff)) << 24) |
           ((value & UINT32_C(0x0000ff00)) << 8) |
           ((value & UINT32_C(0x00ff0000)) >> 8) |
           ((value & UINT32_C(0xff000000)) >> 24);
}


static uint64_t swap_u64(
    uint64_t value
)
{
    return ((value & UINT64_C(0x00000000000000ff)) << 56) |
           ((value & UINT64_C(0x000000000000ff00)) << 40) |
           ((value & UINT64_C(0x0000000000ff0000)) << 24) |
           ((value & UINT64_C(0x00000000ff000000)) << 8) |
           ((value & UINT64_C(0x000000ff00000000)) >> 8) |
           ((value & UINT64_C(0x0000ff0000000000)) >> 24) |
           ((value & UINT64_C(0x00ff000000000000)) >> 40) |
           ((value & UINT64_C(0xff00000000000000)) >> 56);
}


static void compat_set_reason(
    struct snapshot_compat_report *report,
    const char *reason
)
{
    if (report->reason[0] != '\0') {
        return;
    }

    snprintf(
        report->reason,
        sizeof(report->reason),
        "%s",
        reason
    );
}


static int probe_skip_exact(
    FILE *stream,
    uint64_t size
)
{
    unsigned char buffer[4096];

    while (size != 0U) {
        size_t chunk =
            size > sizeof(buffer)
                ? sizeof(buffer)
                : (size_t)size;

        if (fread(
                buffer,
                1,
                chunk,
                stream
            ) != chunk) {

            return -1;
        }

        size -=
            (uint64_t)chunk;
    }

    return 0;
}


int nsdiff_native_probe(
    FILE *stream,
    struct snapshot_compat_report *report,
    char *error_buf,
    size_t error_buf_size
)
{
    struct snapshot_file_header header;

    struct {
        uint32_t extension_size;
        uint32_t reserved;
    } extension_prefix;

    struct snapshot_v3_extension v3_extension;

    unsigned char buffer[4096];
    unsigned char actual_sha256[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ];

    struct nsdiff_sha256_context sha_context;


    uint64_t remaining;
    uint64_t hash;

    int close_stream = 0;
    int source_swapped = 0;
    int extra;

    memset(
        report,
        0,
        sizeof(*report)
    );

    memset(
        &header,
        0,
        sizeof(header)
    );

    if (read_exact(
            stream,
            &header,
            sizeof(header)
        ) != 0) {

        if (close_stream) {
            fclose(stream);
        }

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot header is truncated"
        );

        return -1;
    }

    report->header_read =
        1;

    report->magic_valid =
        memcmp(
            header.magic,
            snapshot_magic,
            sizeof(snapshot_magic)
        ) == 0;

    source_swapped =
        header.endian_marker ==
        swap_u32(NSDIFF_SNAPSHOT_ENDIAN_MARKER);

    report->format_version =
        source_swapped
            ? swap_u32(header.format_version)
            : header.format_version;

    report->abi_version =
        source_swapped
            ? swap_u32(header.abi_version)
            : header.abi_version;

    report->endian_marker =
        header.endian_marker;

    report->snapshot_size =
        source_swapped
            ? swap_u64(header.snapshot_size)
            : header.snapshot_size;

    report->payload_hash =
        source_swapped
            ? swap_u64(header.payload_hash)
            : header.payload_hash;

    memcpy(
        report->tool_version,
        header.tool_version,
        sizeof(report->tool_version)
    );

    report->tool_version[
        sizeof(report->tool_version) - 1U
    ] = '\0';

    report->format_supported =
        report->format_version ==
            SNAPSHOT_FORMAT_V1 ||
        report->format_version ==
            SNAPSHOT_FORMAT_V2 ||
        report->format_version ==
            SNAPSHOT_FORMAT_V3;

    report->abi_supported =
        report->abi_version ==
        NSDIFF_SNAPSHOT_ABI_VERSION;

    report->endian_supported =
        !source_swapped &&
        header.endian_marker ==
        NSDIFF_SNAPSHOT_ENDIAN_MARKER;

    report->snapshot_size_supported =
        report->snapshot_size ==
        (uint64_t)sizeof(struct process_snapshot);

    if (!report->magic_valid) {

        compat_set_reason(
            report,
            "not an nsdiff snapshot"
        );

        goto finish;
    }

    if (!report->format_supported) {

        compat_set_reason(
            report,
            "snapshot format version is unsupported"
        );

        goto finish;
    }

    report->extension_valid =
        1;

    memset(
        &v3_extension,
        0,
        sizeof(v3_extension)
    );

    if (report->format_version ==
            SNAPSHOT_FORMAT_V2 ||
        report->format_version ==
            SNAPSHOT_FORMAT_V3) {

        uint32_t expected_extension_size =
            report->format_version ==
                SNAPSHOT_FORMAT_V2
                    ? (uint32_t)sizeof(
                          struct snapshot_v2_extension
                      )
                    : (uint32_t)sizeof(
                          struct snapshot_v3_extension
                      );

        if (read_exact(
                stream,
                &extension_prefix,
                sizeof(extension_prefix)
            ) != 0) {

            report->extension_valid =
                0;

            compat_set_reason(
                report,
                "snapshot provenance is truncated"
            );

            goto finish;
        }

        if (source_swapped) {

            extension_prefix.extension_size =
                swap_u32(
                    extension_prefix.extension_size
                );
        }

        if (extension_prefix.extension_size !=
            expected_extension_size) {

            report->extension_valid =
                0;

            compat_set_reason(
                report,
                "snapshot provenance size is incompatible"
            );
        }

        if (extension_prefix.extension_size <
                (uint32_t)sizeof(extension_prefix) ||
            extension_prefix.extension_size >
                SNAPSHOT_PROBE_MAX_EXTENSION) {

            goto finish;
        }

        if (report->format_version ==
                SNAPSHOT_FORMAT_V3 &&
            extension_prefix.extension_size ==
                (uint32_t)sizeof(v3_extension)) {

            memcpy(
                &v3_extension,
                &extension_prefix,
                sizeof(extension_prefix)
            );

            if (read_exact(
                    stream,
                    (unsigned char *)&v3_extension +
                        sizeof(extension_prefix),
                    sizeof(v3_extension) -
                        sizeof(extension_prefix)
                ) != 0) {

                report->extension_valid =
                    0;

                compat_set_reason(
                    report,
                    "snapshot provenance is truncated"
                );

                goto finish;
            }

            if (source_swapped) {

                v3_extension.digest_algorithm =
                    swap_u32(
                        v3_extension.digest_algorithm
                    );

                v3_extension.digest_size =
                    swap_u32(
                        v3_extension.digest_size
                    );
            }

            if (v3_extension.digest_algorithm !=
                    SNAPSHOT_DIGEST_SHA256 ||
                v3_extension.digest_size !=
                    NSDIFF_SNAPSHOT_SHA256_LEN) {

                report->extension_valid =
                    0;

                compat_set_reason(
                    report,
                    "snapshot payload digest metadata is incompatible"
                );
            }

        } else {

            if (probe_skip_exact(
                    stream,
                    (uint64_t)extension_prefix.extension_size -
                        (uint64_t)sizeof(extension_prefix)
                ) != 0) {

                report->extension_valid =
                    0;

                compat_set_reason(
                    report,
                    "snapshot provenance is truncated"
                );

                goto finish;
            }
        }
    }

    if (report->snapshot_size >
        SNAPSHOT_PROBE_MAX_PAYLOAD) {

        compat_set_reason(
            report,
            "snapshot payload is too large to probe safely"
        );

        goto finish;
    }

    hash =
        UINT64_C(14695981039346656037);

    if (report->format_version ==
        SNAPSHOT_FORMAT_V3) {

        nsdiff_sha256_init(
            &sha_context
        );
    }

    remaining =
        report->snapshot_size;

    while (remaining != 0U) {
        size_t chunk =
            remaining > sizeof(buffer)
                ? sizeof(buffer)
                : (size_t)remaining;

        size_t got =
            fread(
                buffer,
                1,
                chunk,
                stream
            );

        if (got != chunk) {

            report->payload_complete =
                0;

            compat_set_reason(
                report,
                "snapshot payload is truncated"
            );

            goto finish;
        }

        hash =
            fnv1a64_update(
                hash,
                buffer,
                got
            );

        if (report->format_version ==
            SNAPSHOT_FORMAT_V3) {

            nsdiff_sha256_update(
                &sha_context,
                buffer,
                got
            );
        }

        remaining -=
            (uint64_t)got;
    }

    report->payload_complete =
        1;

    report->checksum_checked =
        1;

    report->checksum_valid =
        hash ==
        report->payload_hash;

    if (report->format_version ==
        SNAPSHOT_FORMAT_V3) {

        nsdiff_sha256_final(
            &sha_context,
            actual_sha256
        );

        report->sha256_checked =
            1;

        report->sha256_valid =
            sha256_equal(
                actual_sha256,
                v3_extension.payload_sha256
            );
    }

    extra =
        fgetc(stream);

    if (extra != EOF) {

        report->trailing_data =
            1;

    } else if (ferror(stream)) {

        if (close_stream) {
            fclose(stream);
        }

        snprintf(
            error_buf,
            error_buf_size,
            "cannot finish probing snapshot"
        );

        return -1;
    }

    if (!report->abi_supported) {

        compat_set_reason(
            report,
            "snapshot ABI version is incompatible"
        );

    } else if (!report->endian_supported) {

        compat_set_reason(
            report,
            "snapshot byte order is incompatible"
        );

    } else if (!report->snapshot_size_supported) {

        compat_set_reason(
            report,
            "snapshot structure size is incompatible"
        );

    } else if (!report->extension_valid) {

        compat_set_reason(
            report,
            "snapshot provenance is incompatible"
        );

    } else if (!report->payload_complete) {

        compat_set_reason(
            report,
            "snapshot payload is truncated"
        );

    } else if (!report->checksum_valid) {

        compat_set_reason(
            report,
            "snapshot payload checksum mismatch"
        );

    } else if (report->format_version ==
                   SNAPSHOT_FORMAT_V3 &&
               (!report->sha256_checked ||
                !report->sha256_valid)) {

        compat_set_reason(
            report,
            "snapshot payload SHA-256 mismatch"
        );

    } else if (report->trailing_data) {

        compat_set_reason(
            report,
            "snapshot contains unexpected trailing data"
        );
    }

    report->compatible =
        report->magic_valid &&
        report->format_supported &&
        report->abi_supported &&
        report->endian_supported &&
        report->snapshot_size_supported &&
        report->extension_valid &&
        report->payload_complete &&
        report->checksum_checked &&
        report->checksum_valid &&
        (report->format_version !=
             SNAPSHOT_FORMAT_V3 ||
         (report->sha256_checked &&
          report->sha256_valid)) &&
        !report->trailing_data;

    if (report->compatible) {

        snprintf(
            report->reason,
            sizeof(report->reason),
            "compatible"
        );
    }

finish:

    if (close_stream &&
        fclose(stream) != 0) {

        snprintf(
            error_buf,
            error_buf_size,
            "cannot close snapshot: %s",
            strerror(errno)
        );

        return -1;
    }

    return 0;
}


int nsdiff_native_save(
    const char *path,
    const struct process_snapshot *snapshot,
    const struct snapshot_metadata *metadata,
    char *error_buf,
    size_t error_buf_size
)
{
    struct snapshot_file_header header = {0};

    struct snapshot_v3_extension extension;

    struct process_snapshot copy;

    unsigned char *data;
    size_t size = sizeof(header) + sizeof(extension) + sizeof(copy);
    int rc;
    memset(
        &copy,
        0,
        sizeof(copy)
    );

    memcpy(
        &copy,
        snapshot,
        sizeof(copy)
    );

    copy.pidfd = -1;

    if (collect_v3_extension(
            &extension,
            error_buf,
            error_buf_size
        ) != 0) {

        return -1;
    }

    if (metadata != NULL) {
        /* v3's zero provenance sentinel represents an unknown original capture. */
        extension.captured_sec = metadata->have_provenance ? metadata->captured_sec : 0;
        extension.captured_nsec = metadata->have_provenance ? metadata->captured_nsec : 0;
        memset(extension.kernel_release, 0, sizeof(extension.kernel_release));
        memset(extension.machine, 0, sizeof(extension.machine));
        if (metadata->have_provenance) {
            memcpy(extension.kernel_release, metadata->kernel_release, sizeof(extension.kernel_release));
            memcpy(extension.machine, metadata->machine, sizeof(extension.machine));
        }
    }
    extension.digest_algorithm =
        SNAPSHOT_DIGEST_SHA256;

    extension.digest_size =
        NSDIFF_SNAPSHOT_SHA256_LEN;

    nsdiff_sha256(
        &copy,
        sizeof(copy),
        extension.payload_sha256
    );

    memcpy(
        header.magic,
        snapshot_magic,
        sizeof(header.magic)
    );

    header.format_version =
        NSDIFF_SNAPSHOT_FORMAT_VERSION;

    header.abi_version =
        NSDIFF_SNAPSHOT_ABI_VERSION;

    header.endian_marker =
        NSDIFF_SNAPSHOT_ENDIAN_MARKER;

    header.snapshot_size =
        (uint64_t)sizeof(copy);

    header.payload_hash =
        fnv1a64(
            &copy,
            sizeof(copy)
        );

    snprintf(
        header.tool_version,
        sizeof(header.tool_version),
        "%s",
        NSDIFF_VERSION
    );

    data = malloc(size);
    if (data == NULL) {
        snprintf(error_buf, error_buf_size, "cannot allocate native output");
        return -1;
    }
    memcpy(data, &header, sizeof(header));
    memcpy(data + sizeof(header), &extension, sizeof(extension));
    memcpy(data + sizeof(header) + sizeof(extension), &copy, sizeof(copy));
    rc = nsdiff_write_private(path, data, size, error_buf, error_buf_size);
    free(data);
    return rc;
}

int nsdiff_native_load(
    FILE *stream,
    struct process_snapshot *snapshot,
    char *error_buf,
    size_t error_buf_size
)
{
    struct snapshot_file_header header;

    struct snapshot_v3_extension extension;

    uint64_t actual_hash;

    if (read_snapshot_file(
            stream,
            &header,
            &extension,
            snapshot,
            error_buf,
            error_buf_size
        ) != 0) {

        return -1;
    }

    actual_hash =
        fnv1a64(
            snapshot,
            sizeof(*snapshot)
        );

    if (actual_hash !=
        header.payload_hash) {

        reset_snapshot(snapshot);

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot payload checksum mismatch"
        );

        return -1;
    }

    if (header.format_version ==
        SNAPSHOT_FORMAT_V3) {

        unsigned char actual_sha256[
            NSDIFF_SNAPSHOT_SHA256_LEN
        ];

        nsdiff_sha256(
            snapshot,
            sizeof(*snapshot),
            actual_sha256
        );

        if (!sha256_equal(
                actual_sha256,
                extension.payload_sha256
            )) {

            reset_snapshot(snapshot);

            snprintf(
                error_buf,
                error_buf_size,
                "snapshot payload SHA-256 mismatch"
            );

            return -1;
        }
    }

    if (snapshot_validate(snapshot, error_buf, error_buf_size) != 0) return -1;

    if (snapshot->pid <= 0) {

        reset_snapshot(snapshot);

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot contains an invalid PID"
        );

        return -1;
    }

    if (snapshot->starttime_ticks ==
        0ULL) {

        reset_snapshot(snapshot);

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot contains invalid process identity"
        );

        return -1;
    }

    snapshot->pidfd = -1;

    return 0;
}


int nsdiff_native_identity(
    FILE *stream,
    struct snapshot_identity *identity,
    char *error_buf,
    size_t error_buf_size
)
{
    struct snapshot_file_header header;

    struct snapshot_v3_extension extension;

    struct process_snapshot snapshot;

    uint64_t actual_hash;

    unsigned char actual_sha256[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ];

    memset(
        identity,
        0,
        sizeof(*identity)
    );

    if (read_snapshot_file(
            stream,
            &header,
            &extension,
            &snapshot,
            error_buf,
            error_buf_size
        ) != 0) {

        return -1;
    }

    actual_hash =
        fnv1a64(
            &snapshot,
            sizeof(snapshot)
        );

    if (actual_hash !=
        header.payload_hash) {

        reset_snapshot(
            &snapshot
        );

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot payload checksum mismatch"
        );

        return -1;
    }

    nsdiff_sha256(
        &snapshot,
        sizeof(snapshot),
        actual_sha256
    );

    if (header.format_version ==
            SNAPSHOT_FORMAT_V3 &&
        !sha256_equal(
            actual_sha256,
            extension.payload_sha256
        )) {

        reset_snapshot(
            &snapshot
        );

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot payload SHA-256 mismatch"
        );

        return -1;
    }

    if (snapshot_validate(&snapshot, error_buf, error_buf_size) != 0) return -1;

    if (snapshot.pid <= 0) {

        reset_snapshot(
            &snapshot
        );

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot contains an invalid PID"
        );

        return -1;
    }

    if (snapshot.starttime_ticks ==
        0ULL) {

        reset_snapshot(
            &snapshot
        );

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot contains invalid process identity"
        );

        return -1;
    }

    identity->format_version =
        header.format_version;

    identity->abi_version =
        header.abi_version;

    identity->snapshot_size =
        header.snapshot_size;

    identity->payload_hash =
        header.payload_hash;

    identity->pid =
        snapshot.pid;

    identity->starttime_ticks =
        snapshot.starttime_ticks;

    identity->checksum_valid =
        1;

    snprintf(
        identity->tool_version,
        sizeof(identity->tool_version),
        "%s",
        header.tool_version
    );

    memcpy(
        identity->payload_sha256,
        actual_sha256,
        sizeof(identity->payload_sha256)
    );

    if (header.format_version ==
        SNAPSHOT_FORMAT_V3) {

        identity->have_stored_sha256 =
            1;

        identity->stored_sha256_valid =
            1;

        memcpy(
            identity->stored_sha256,
            extension.payload_sha256,
            sizeof(identity->stored_sha256)
        );
    }

    if (header.format_version ==
            SNAPSHOT_FORMAT_V2 ||
        header.format_version ==
            SNAPSHOT_FORMAT_V3) {

        identity->have_provenance =
            extension.captured_sec != 0 || extension.captured_nsec != 0 ||
            extension.kernel_release[0] != 0 || extension.machine[0] != 0;

        identity->captured_sec =
            extension.captured_sec;

        identity->captured_nsec =
            extension.captured_nsec;

        snprintf(
            identity->kernel_release,
            sizeof(identity->kernel_release),
            "%s",
            extension.kernel_release
        );

        snprintf(
            identity->machine,
            sizeof(identity->machine),
            "%s",
            extension.machine
        );
    }

    return 0;
}


int nsdiff_native_inspect(
    FILE *stream,
    struct snapshot_metadata *metadata,
    char *error_buf,
    size_t error_buf_size
)
{
    struct snapshot_file_header header;

    struct snapshot_v3_extension extension;

    struct process_snapshot snapshot;

    uint64_t actual_hash;

    unsigned char actual_sha256[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ];

    memset(
        metadata,
        0,
        sizeof(*metadata)
    );

    if (read_snapshot_file(
            stream,
            &header,
            &extension,
            &snapshot,
            error_buf,
            error_buf_size
        ) != 0) {

        return -1;
    }

    actual_hash =
        fnv1a64(
            &snapshot,
            sizeof(snapshot)
        );

    metadata->format_version =
        header.format_version;

    metadata->abi_version =
        header.abi_version;

    metadata->snapshot_size =
        header.snapshot_size;

    metadata->payload_hash =
        header.payload_hash;

    snprintf(
        metadata->tool_version,
        sizeof(metadata->tool_version),
        "%s",
        header.tool_version
    );

    metadata->pid =
        snapshot.pid;

    metadata->starttime_ticks =
        snapshot.starttime_ticks;

    metadata->checksum_valid =
        actual_hash ==
        header.payload_hash;

    if (!metadata->checksum_valid) {

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot payload checksum mismatch"
        );

        return -1;
    }

    if (header.format_version ==
        SNAPSHOT_FORMAT_V3) {

        metadata->have_sha256 =
            1;

        memcpy(
            metadata->payload_sha256,
            extension.payload_sha256,
            sizeof(metadata->payload_sha256)
        );

        nsdiff_sha256(
            &snapshot,
            sizeof(snapshot),
            actual_sha256
        );

        metadata->sha256_valid =
            sha256_equal(
                actual_sha256,
                extension.payload_sha256
            );

        if (!metadata->sha256_valid) {

            snprintf(
                error_buf,
                error_buf_size,
                "snapshot payload SHA-256 mismatch"
            );

            return -1;
        }
    }

    if (snapshot_validate(&snapshot, error_buf, error_buf_size) != 0) return -1;

    if (metadata->pid <= 0 ||
        metadata->starttime_ticks == 0ULL) {

        snprintf(
            error_buf,
            error_buf_size,
            "snapshot metadata is invalid"
        );

        return -1;
    }

    if (header.format_version ==
            SNAPSHOT_FORMAT_V2 ||
        header.format_version ==
            SNAPSHOT_FORMAT_V3) {

        metadata->have_provenance =
            extension.captured_sec != 0 || extension.captured_nsec != 0 ||
            extension.kernel_release[0] != 0 || extension.machine[0] != 0;

        metadata->captured_sec =
            extension.captured_sec;

        metadata->captured_nsec =
            extension.captured_nsec;

        snprintf(
            metadata->kernel_release,
            sizeof(metadata->kernel_release),
            "%s",
            extension.kernel_release
        );

        snprintf(
            metadata->machine,
            sizeof(metadata->machine),
            "%s",
            extension.machine
        );
    }

    return 0;
}

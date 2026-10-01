#ifndef NSDIFF_SNAPSHOT_IO_H
#define NSDIFF_SNAPSHOT_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "nsdiff/snapshot.h"


#define NSDIFF_SNAPSHOT_FORMAT_VERSION 3U
#define NSDIFF_SNAPSHOT_MIN_FORMAT_VERSION 1U
#define NSDIFF_SNAPSHOT_ABI_VERSION 1U
#define NSDIFF_SNAPSHOT_ENDIAN_MARKER UINT32_C(0x01020304)

#define NSDIFF_SNAPSHOT_VERSION_LEN 32U
#define NSDIFF_SNAPSHOT_KERNEL_LEN 128U
#define NSDIFF_SNAPSHOT_MACHINE_LEN 64U
#define NSDIFF_SNAPSHOT_SHA256_LEN 32U


#define NSDIFF_SNAPSHOT_COMPAT_REASON_LEN 160U


struct snapshot_compat_report {
    bool portable;
    int header_read;
    int magic_valid;

    uint32_t format_version;
    uint32_t abi_version;
    uint32_t endian_marker;

    uint64_t snapshot_size;
    uint64_t payload_hash;

    char tool_version[
        NSDIFF_SNAPSHOT_VERSION_LEN
    ];

    int format_supported;
    int abi_supported;
    int endian_supported;
    int snapshot_size_supported;

    int extension_valid;
    int payload_complete;

    int checksum_checked;
    int checksum_valid;

    int sha256_checked;
    int sha256_valid;

    int trailing_data;
    int compatible;

    char reason[
        NSDIFF_SNAPSHOT_COMPAT_REASON_LEN
    ];
};


struct snapshot_identity {
    bool portable;
    uint32_t format_version;
    uint32_t abi_version;

    uint64_t snapshot_size;
    uint64_t payload_hash;

    pid_t pid;

    unsigned long long starttime_ticks;

    char tool_version[
        NSDIFF_SNAPSHOT_VERSION_LEN
    ];

    /*
     * Computed over the raw native payload for every
     * supported format, including legacy v1/v2 snapshots.
     */
    unsigned char payload_sha256[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ];

    int checksum_valid;

    /*
     * v3+ stores SHA-256 in the container. v1/v2 do not,
     * but payload_sha256 above is still computed.
     */
    int have_stored_sha256;
    int stored_sha256_valid;

    unsigned char stored_sha256[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ];

    int have_provenance;

    int64_t captured_sec;
    int32_t captured_nsec;

    char kernel_release[
        NSDIFF_SNAPSHOT_KERNEL_LEN
    ];

    char machine[
        NSDIFF_SNAPSHOT_MACHINE_LEN
    ];
};


struct snapshot_metadata {
    bool portable;
    uint32_t format_version;
    uint32_t abi_version;

    uint64_t snapshot_size;
    uint64_t payload_hash;

    char tool_version[
        NSDIFF_SNAPSHOT_VERSION_LEN
    ];

    pid_t pid;

    unsigned long long starttime_ticks;

    int checksum_valid;

    int have_sha256;
    int sha256_valid;
    unsigned char payload_sha256[
        NSDIFF_SNAPSHOT_SHA256_LEN
    ];

    int have_provenance;

    int64_t captured_sec;
    int32_t captured_nsec;

    char kernel_release[
        NSDIFF_SNAPSHOT_KERNEL_LEN
    ];

    char machine[
        NSDIFF_SNAPSHOT_MACHINE_LEN
    ];
};


int process_snapshot_save(
    const char *path,
    const struct process_snapshot *snapshot,
    char *error_buf,
    size_t error_buf_size
);


int process_snapshot_load(
    const char *path,
    struct process_snapshot *snapshot,
    char *error_buf,
    size_t error_buf_size
);


int process_snapshot_identity(
    const char *path,
    struct snapshot_identity *identity,
    char *error_buf,
    size_t error_buf_size
);


int process_snapshot_inspect(
    const char *path,
    struct snapshot_metadata *metadata,
    char *error_buf,
    size_t error_buf_size
);


int process_snapshot_probe(
    const char *path,
    struct snapshot_compat_report *report,
    char *error_buf,
    size_t error_buf_size
);


#endif

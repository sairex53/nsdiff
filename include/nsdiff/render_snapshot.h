#ifndef NSDIFF_RENDER_SNAPSHOT_H
#define NSDIFF_RENDER_SNAPSHOT_H

#include <stdbool.h>

#include "nsdiff/snapshot_io.h"


void render_snapshot_manifest(
    const char *path,
    const struct snapshot_identity *identity
);


void render_snapshot_manifest_json(
    const char *path,
    const struct snapshot_identity *identity,
    const char *error
);


void render_snapshot_identity(
    const char *path,
    const struct snapshot_identity *identity
);


void render_snapshot_identity_json(
    const char *path,
    const struct snapshot_identity *identity,
    const char *error
);


void render_snapshot_metadata(
    const char *path,
    const struct snapshot_metadata *metadata
);


void render_snapshot_metadata_json(
    const char *path,
    const struct snapshot_metadata *metadata,
    const char *error
);


void render_snapshot_verification_json(
    const char *path,
    bool valid,
    const char *error
);


void render_snapshot_compatibility(
    const char *path,
    const struct snapshot_compat_report *report
);


void render_snapshot_compatibility_json(
    const char *path,
    const struct snapshot_compat_report *report,
    const char *error
);


void render_snapshot_schema(void);


void render_snapshot_schema_json(void);


#endif

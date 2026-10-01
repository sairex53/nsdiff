#include <errno.h>
#include <signal.h>
#include "nsdiff/snapshot_internal.h"
#include "nsdiff/json_writer.h"
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "nsdiff/diff.h"
#include "nsdiff/diff_summary.h"
#include "nsdiff/process.h"
#include "nsdiff/render.h"
#include "nsdiff/render_compact.h"
#include "nsdiff/render_json.h"
#include "nsdiff/render_summary.h"
#include "nsdiff/scope.h"
#include "nsdiff/snapshot_io.h"
#include "nsdiff/render_snapshot.h"


enum output_mode {
    OUTPUT_TEXT = 0,
    OUTPUT_JSON,
    OUTPUT_COMPACT,
    OUTPUT_EXPLAIN,
    OUTPUT_SUMMARY,
    OUTPUT_QUIET,
};


enum input_mode {
    INPUT_LIVE_LIVE = 0,
    INPUT_AGAINST_SNAPSHOT,
    INPUT_SNAPSHOT_SNAPSHOT,
    INPUT_CAPTURE,
    INPUT_CONVERT,
    INPUT_SEMANTIC_ID,
    INPUT_SNAPSHOT_INFO,
    INPUT_SNAPSHOT_VERIFY,
    INPUT_SNAPSHOT_COMPAT,
    INPUT_SNAPSHOT_ID,
    INPUT_SNAPSHOT_MANIFEST,
    INPUT_SNAPSHOT_SCHEMA,
    INPUT_SNAPSHOT_EXPORT_JSON,
};


struct cli_options {
    enum output_mode output;
    enum input_mode input;

    bool output_explicit;
    bool format_explicit;
    bool portable;
    bool input_explicit;

    bool show_help;
    bool show_version;

    bool section_explicit;

    nsdiff_section_mask sections;

    const char *snapshot_a_path;
    const char *snapshot_b_path;
    const char *capture_path;
    const char *inspect_path;
    const char *export_path;

    const char *pid_text[2];

    unsigned int pid_count;
};


static int parse_pid(
    const char *text,
    pid_t *pid_out
)
{
    char *end = NULL;

    long value;

    errno = 0;

    value = strtol(
        text,
        &end,
        10
    );

    if (errno != 0 ||
        end == text ||
        *end != '\0' ||
        value <= 0 ||
        value > INT_MAX) {

        return -1;
    }

    *pid_out =
        (pid_t)value;

    return 0;
}


static void usage(
    FILE *stream,
    const char *program
)
{
    fprintf(
        stream,
        "Usage:\n"
        "  %s [OPTIONS] PID_A PID_B\n"
        "  %s [OPTIONS] --against SNAPSHOT PID\n"
        "  %s [OPTIONS] --snapshots SNAPSHOT_A SNAPSHOT_B\n"
        "  %s --capture SNAPSHOT PID\n"
        "  %s [--json] --snapshot-info SNAPSHOT\n"
        "  %s [--json] --verify-snapshot SNAPSHOT\n"
        "  %s [--json] --snapshot-compat SNAPSHOT\n"
        "  %s [--json] --snapshot-id SNAPSHOT\n"
        "  %s [--json] --snapshot-manifest SNAPSHOT\n"
        "  %s [--json] --snapshot-schema\n"
        "  %s --export-snapshot-json SNAPSHOT\n"
        "\n"
        "Compare Linux process execution environments.\n"
        "\n"
        "Snapshot operations:\n"
        "  --capture FILE         capture one live process (native v3 by default)\n"
        "  --snapshot-format native|portable\n"
        "                         format for capture or conversion\n"
        "  --convert-snapshot IN OUT --snapshot-format FORMAT\n"
        "                         lossless conversion; supports - for streams\n"
        "  --semantic-id FILE     architecture-independent identity; supports --json\n"
        "  --against FILE         compare saved FILE with live PID\n"
        "  --snapshots A B        compare two saved snapshots\n"
        "  --snapshot-info FILE   display snapshot metadata; supports --json\n"
        "  --verify-snapshot FILE validate snapshot integrity; supports --json\n"
        "  --snapshot-compat FILE inspect snapshot compatibility; supports --json\n"
        "  --snapshot-id FILE     print stable payload identity; supports --json\n"
        "  --snapshot-manifest FILE\n"
        "                         print identity, integrity and provenance; supports --json\n"
        "  --snapshot-schema      show supported snapshot/schema contract; supports --json\n"
        "  --export-snapshot-json FILE\n"
        "                         redacted diagnostic JSON; not an importable snapshot\n"
        "  FILE may be -         use stdin/stdout for snapshot data\n"
        "\n"
        "Output modes:\n"
        "  --json                 machine-readable JSON\n"
        "  --only-differences     show only semantic differences\n"
        "  --explain              differences plus explanations\n"
        "  --summary              per-domain comparison summary\n"
        "  -q, --quiet            no normal output; use exit status only\n"
        "\n"
        "Scope:\n"
        "  --section NAME         compare only one domain; may be repeated\n"
        "\n"
        "Sections:\n"
        "  namespaces\n"
        "  credentials\n"
        "  limits\n"
        "  cgroup\n"
        "  network\n"
        "  mounts\n"
        "  environment\n"
        "  security\n"
        "  all\n"
        "\n"
        "Other options:\n"
        "  -h, --help             show this help\n"
        "  -V, --version          show version\n"
        "\n"
        "Exit status:\n"
        "  0  operation succeeded / comparison has no differences\n"
        "  1  comparison completed and differences were found\n"
        "  2  invalid input, failed capture or invalid snapshot\n",
        program,
        program,
        program,
        program,
        program,
        program,
        program,
        program,
        program,
        program,
        program
    );
}

static int set_output_mode(
    struct cli_options *options,
    enum output_mode mode,
    const char *option
)
{
    if (options->output_explicit &&
        options->output != mode) {

        fprintf(
            stderr,
            "nsdiff: conflicting output option: %s\n",
            option
        );

        return -1;
    }

    options->output =
        mode;

    options->output_explicit =
        true;

    return 0;
}


static int set_input_mode(
    struct cli_options *options,
    enum input_mode mode,
    const char *option
)
{
    if (options->input_explicit &&
        options->input != mode) {

        fprintf(
            stderr,
            "nsdiff: conflicting input option: %s\n",
            option
        );

        return -1;
    }

    if (options->input_explicit) {

        fprintf(
            stderr,
            "nsdiff: input mode specified more than once: %s\n",
            option
        );

        return -1;
    }

    options->input =
        mode;

    options->input_explicit =
        true;

    return 0;
}


static int add_section(
    struct cli_options *options,
    const char *name
)
{
    nsdiff_section_mask section;

    if (nsdiff_section_parse(
            name,
            &section
        ) != 0) {

        fprintf(
            stderr,
            "nsdiff: unknown section: %s\n",
            name
        );

        return -1;
    }

    if (!options->section_explicit) {

        options->sections = 0U;
        options->section_explicit = true;
    }

    options->sections |=
        section;

    return 0;
}


static int parse_cli(
    int argc,
    char **argv,
    struct cli_options *options
)
{
    int i;

    bool end_options = false;

    memset(
        options,
        0,
        sizeof(*options)
    );

    options->output =
        OUTPUT_TEXT;

    options->input =
        INPUT_LIVE_LIVE;

    options->sections =
        NSDIFF_SECTION_ALL;

    for (i = 1;
         i < argc;
         i++) {

        const char *arg =
            argv[i];

        if (!end_options &&
            strcmp(
                arg,
                "--"
            ) == 0) {

            end_options = true;

            continue;
        }

        if (!end_options && strcmp(arg, "--snapshot-format") == 0) {
            if (options->format_explicit || i+1 >= argc) {
                fprintf(stderr, "nsdiff: --snapshot-format requires one native or portable value\n");
                return -1;
            }
            const char *format = argv[++i];
            if (strcmp(format, "native") && strcmp(format, "portable")) {
                fprintf(stderr, "nsdiff: snapshot format must be native or portable\n");
                return -1;
            }
            options->format_explicit = true;
            options->portable = !strcmp(format, "portable");
            continue;
        }
        if (!end_options && strcmp(arg, "--convert-snapshot") == 0) {
            if (i+2 >= argc || set_input_mode(options, INPUT_CONVERT, arg)) return -1;
            options->snapshot_a_path = argv[++i];
            options->capture_path = argv[++i];
            continue;
        }
        if (!end_options && strcmp(arg, "--semantic-id") == 0) {
            if (i+1 >= argc || set_input_mode(options, INPUT_SEMANTIC_ID, arg)) return -1;
            options->inspect_path = argv[++i];
            continue;
        }
        if (!end_options &&
            strcmp(
                arg,
                "--json"
            ) == 0) {

            if (set_output_mode(
                    options,
                    OUTPUT_JSON,
                    arg
                ) != 0) {

                return -1;
            }

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--only-differences"
            ) == 0) {

            if (set_output_mode(
                    options,
                    OUTPUT_COMPACT,
                    arg
                ) != 0) {

                return -1;
            }

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--explain"
            ) == 0) {

            if (set_output_mode(
                    options,
                    OUTPUT_EXPLAIN,
                    arg
                ) != 0) {

                return -1;
            }

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--summary"
            ) == 0) {

            if (set_output_mode(
                    options,
                    OUTPUT_SUMMARY,
                    arg
                ) != 0) {

                return -1;
            }

            continue;
        }

        if (!end_options &&
            (strcmp(
                 arg,
                 "--quiet"
             ) == 0 ||
             strcmp(
                 arg,
                 "-q"
             ) == 0)) {

            if (set_output_mode(
                    options,
                    OUTPUT_QUIET,
                    arg
                ) != 0) {

                return -1;
            }

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--capture"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --capture requires a file\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_CAPTURE,
                    arg
                ) != 0) {

                return -1;
            }

            options->capture_path =
                argv[++i];

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--against"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --against requires a snapshot file\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_AGAINST_SNAPSHOT,
                    arg
                ) != 0) {

                return -1;
            }

            options->snapshot_a_path =
                argv[++i];

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--snapshots"
            ) == 0) {

            if (i + 2 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --snapshots requires two snapshot files\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_SNAPSHOT_SNAPSHOT,
                    arg
                ) != 0) {

                return -1;
            }

            options->snapshot_a_path =
                argv[++i];

            options->snapshot_b_path =
                argv[++i];

            continue;
        }

		        if (!end_options &&
            strcmp(
                arg,
                "--snapshot-info"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --snapshot-info requires a file\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_SNAPSHOT_INFO,
                    arg
                ) != 0) {

                return -1;
            }

            options->inspect_path =
                argv[++i];

            continue;
        }


        if (!end_options &&
            strcmp(
                arg,
                "--verify-snapshot"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --verify-snapshot requires a file\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_SNAPSHOT_VERIFY,
                    arg
                ) != 0) {

                return -1;
            }

            options->inspect_path =
                argv[++i];

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--snapshot-compat"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --snapshot-compat requires a file\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_SNAPSHOT_COMPAT,
                    arg
                ) != 0) {

                return -1;
            }

            options->inspect_path =
                argv[++i];

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--snapshot-id"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --snapshot-id requires a file\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_SNAPSHOT_ID,
                    arg
                ) != 0) {

                return -1;
            }

            options->inspect_path =
                argv[++i];

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--snapshot-manifest"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --snapshot-manifest requires a file\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_SNAPSHOT_MANIFEST,
                    arg
                ) != 0) {

                return -1;
            }

            options->inspect_path =
                argv[++i];

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--snapshot-schema"
            ) == 0) {

            if (set_input_mode(
                    options,
                    INPUT_SNAPSHOT_SCHEMA,
                    arg
                ) != 0) {

                return -1;
            }

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--export-snapshot-json"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --export-snapshot-json requires a file\n"
                );

                return -1;
            }

            if (set_input_mode(
                    options,
                    INPUT_SNAPSHOT_EXPORT_JSON,
                    arg
                ) != 0) {

                return -1;
            }

            options->export_path =
                argv[++i];

            continue;
        }

        if (!end_options &&
            strcmp(
                arg,
                "--section"
            ) == 0) {

            if (i + 1 >= argc) {

                fprintf(
                    stderr,
                    "nsdiff: --section requires a name\n"
                );

                return -1;
            }

            if (add_section(
                    options,
                    argv[++i]
                ) != 0) {

                return -1;
            }

            continue;
        }

        if (!end_options &&
            strncmp(
                arg,
                "--section=",
                strlen("--section=")
            ) == 0) {

            const char *name =
                arg + strlen("--section=");

            if (*name == '\0') {

                fprintf(
                    stderr,
                    "nsdiff: --section requires a name\n"
                );

                return -1;
            }

            if (add_section(
                    options,
                    name
                ) != 0) {

                return -1;
            }

            continue;
        }

        if (!end_options &&
            (strcmp(
                 arg,
                 "--help"
             ) == 0 ||
             strcmp(
                 arg,
                 "-h"
             ) == 0)) {

            options->show_help =
                true;

            continue;
        }

        if (!end_options &&
            (strcmp(
                 arg,
                 "--version"
             ) == 0 ||
             strcmp(
                 arg,
                 "-V"
             ) == 0)) {

            options->show_version =
                true;

            continue;
        }

        if (!end_options &&
            arg[0] == '-') {

            fprintf(
                stderr,
                "nsdiff: unknown option: %s\n",
                arg
            );

            return -1;
        }

        if (options->pid_count >= 2U) {

            fprintf(
                stderr,
                "nsdiff: too many positional arguments\n"
            );

            return -1;
        }

        options->pid_text[
            options->pid_count++
        ] = arg;
    }

    if (options->format_explicit && options->input != INPUT_CAPTURE && options->input != INPUT_CONVERT) {
        fprintf(stderr, "nsdiff: --snapshot-format requires capture or conversion\n");
        return -1;
    }
    if (options->input == INPUT_CONVERT && (!options->format_explicit || options->pid_count ||
        options->output_explicit || options->section_explicit)) {
        fprintf(stderr, "nsdiff: conversion requires --snapshot-format and no comparison options\n");
        return -1;
    }
    if (options->input == INPUT_SEMANTIC_ID && (options->pid_count || options->section_explicit ||
        (options->output_explicit && options->output != OUTPUT_JSON))) return -1;
    if ((options->input ==
             INPUT_CAPTURE ||
         options->input ==
             INPUT_SNAPSHOT_EXPORT_JSON) &&
        (options->output_explicit ||
         options->section_explicit)) {

        fprintf(
            stderr,
            "nsdiff: this snapshot operation cannot be combined with output or section options\n"
        );

        return -1;
    }

    if ((options->input ==
             INPUT_SNAPSHOT_INFO ||
         options->input ==
             INPUT_SNAPSHOT_VERIFY ||
         options->input ==
             INPUT_SNAPSHOT_COMPAT ||
         options->input ==
             INPUT_SNAPSHOT_ID ||
         options->input ==
             INPUT_SNAPSHOT_MANIFEST ||
         options->input ==
             INPUT_SNAPSHOT_SCHEMA) &&
        options->section_explicit) {

        fprintf(
            stderr,
            "nsdiff: snapshot metadata operations cannot be combined with --section\n"
        );

        return -1;
    }

    if ((options->input ==
             INPUT_SNAPSHOT_INFO ||
         options->input ==
             INPUT_SNAPSHOT_VERIFY ||
         options->input ==
             INPUT_SNAPSHOT_COMPAT ||
         options->input ==
             INPUT_SNAPSHOT_ID ||
         options->input ==
             INPUT_SNAPSHOT_MANIFEST ||
         options->input ==
             INPUT_SNAPSHOT_SCHEMA) &&
        options->output_explicit &&
        options->output != OUTPUT_JSON) {

        fprintf(
            stderr,
            "nsdiff: snapshot metadata operations only support --json as an output mode\n"
        );

        return -1;
    }

    return 0;
}


static int collect_live(
    const char *pid_text,
    struct process_snapshot *snapshot,
    char *error_buf,
    size_t error_buf_size
)
{
    pid_t pid;

    if (parse_pid(
            pid_text,
            &pid
        ) != 0) {

        snprintf(
            error_buf,
            error_buf_size,
            "PID must be a positive number"
        );

        return -1;
    }

    return process_snapshot_collect(
        pid,
        snapshot,
        error_buf,
        error_buf_size
    );
}


static int run_cli(
    int argc,
    char **argv
)
{
    struct cli_options options;

    struct process_snapshot a = {0};
    struct process_snapshot b = {0};

    struct process_diff diff = {0};
    struct process_diff scoped_diff = {0};

    struct process_diff_summary summary = {0};

    struct snapshot_metadata metadata = {0};
    struct snapshot_compat_report compat_report = {0};
    struct snapshot_identity identity = {0};

    const struct process_diff *active_diff;

    char error_buf[256];

    int rc = 2;

    signal(SIGPIPE, SIG_IGN);
    a.pidfd = -1;
    b.pidfd = -1;

    if (parse_cli(
            argc,
            argv,
            &options
        ) != 0) {

        usage(
            stderr,
            argv[0]
        );

        return 2;
    }

    if (options.show_help) {

        usage(
            stdout,
            argv[0]
        );

        return 0;
    }

    if (options.show_version) {

        printf(
            "nsdiff %s\n",
            NSDIFF_VERSION
        );

        return 0;
    }

    if (options.section_explicit &&
        options.output ==
            OUTPUT_JSON) {

        fprintf(
            stderr,
            "nsdiff: --json cannot currently be combined with --section\n"
        );

        return 2;
    }

    if (options.section_explicit &&
        !options.output_explicit) {

        options.output =
            OUTPUT_COMPACT;
    }

    if (options.input == INPUT_CONVERT || options.input == INPUT_SEMANTIC_ID) {
        const char *path = options.input == INPUT_CONVERT ? options.snapshot_a_path : options.inspect_path;
        if (snapshot_load_document(path, &a, &metadata, error_buf, sizeof(error_buf))) {
            if (options.output == OUTPUT_JSON) render_snapshot_verification_json(path, false, error_buf);
            else fprintf(stderr, "nsdiff: %s\n", error_buf);
            goto out;
        }
        if (options.input == INPUT_CONVERT) {
            if (snapshot_save_document(options.capture_path, &a, &metadata, options.portable, error_buf, sizeof(error_buf))) {
                fprintf(stderr, "nsdiff: %s\n", error_buf);
                goto out;
            }
        } else {
            unsigned char digest[32];
            if (snapshot_semantic_digest(&a, digest)) {
                if (options.output == OUTPUT_JSON) render_snapshot_verification_json(path, false, "cannot compute semantic identity");
                else fprintf(stderr, "nsdiff: cannot compute semantic identity\n");
                goto out;
            }
            if (options.output == OUTPUT_JSON) fputs("{\"schema_version\":1,\"document_type\":\"nsdiff-semantic-identity\",\"valid\":true,\"id\":\"", stdout);
            fputs("nsdiff:semantic-sha256:", stdout);
            for (size_t i = 0; i < sizeof(digest); ++i) printf("%02x", digest[i]);
            fputs(options.output == OUTPUT_JSON ? "\"}\n" : "\n", stdout);
        }
        rc = 0;
        goto out;
    }

    /*
     * Capture mode.
     */

    if (options.input ==
        INPUT_CAPTURE) {

        if (options.pid_count != 1U) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (collect_live(
                options.pid_text[0],
                &a,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: %s\n",
                error_buf
            );

            goto out;
        }

        if (snapshot_save_document(
                options.capture_path,
                &a,
                NULL,
                options.portable,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: %s: %s\n",
                options.capture_path,
                error_buf
            );

            goto out;
        }

        if (strcmp(
                options.capture_path,
                "-"
            ) == 0) {

            fprintf(
                stderr,
                "nsdiff: captured PID %ld to stdout\n",
                (long)a.pid
            );

        } else {

            printf(
                "nsdiff: captured PID %ld to %s\n",
                (long)a.pid,
                options.capture_path
            );
        }

        rc = 0;

        goto out;
    }

    /*
     * One-pass snapshot manifest.
     */

    if (options.input ==
        INPUT_SNAPSHOT_MANIFEST) {

        bool manifest_json =
            options.output_explicit &&
            options.output == OUTPUT_JSON;

        if (options.pid_count != 0U ||
            options.section_explicit ||
            (options.output_explicit &&
             options.output != OUTPUT_JSON)) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (process_snapshot_identity(
                options.inspect_path,
                &identity,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            if (manifest_json) {

                render_snapshot_manifest_json(
                    options.inspect_path,
                    NULL,
                    error_buf
                );

            } else {

                fprintf(
                    stderr,
                    "nsdiff: %s: %s\n",
                    options.inspect_path,
                    error_buf
                );
            }

            return 2;
        }

        if (manifest_json) {

            render_snapshot_manifest_json(
                options.inspect_path,
                &identity,
                NULL
            );

        } else {

            render_snapshot_manifest(
                options.inspect_path,
                &identity
            );
        }

        return 0;
    }

    /*
     * Stable snapshot payload identity.
     */

    if (options.input ==
        INPUT_SNAPSHOT_ID) {

        bool identity_json =
            options.output_explicit &&
            options.output == OUTPUT_JSON;

        if (options.pid_count != 0U ||
            options.section_explicit ||
            (options.output_explicit &&
             options.output != OUTPUT_JSON)) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (process_snapshot_identity(
                options.inspect_path,
                &identity,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            if (identity_json) {

                render_snapshot_identity_json(
                    options.inspect_path,
                    NULL,
                    error_buf
                );

            } else {

                fprintf(
                    stderr,
                    "nsdiff: %s: %s\n",
                    options.inspect_path,
                    error_buf
                );
            }

            return 2;
        }

        if (identity_json) {

            render_snapshot_identity_json(
                options.inspect_path,
                &identity,
                NULL
            );

        } else {

            render_snapshot_identity(
                options.inspect_path,
                &identity
            );
        }

        return 0;
    }

    /*
     * Snapshot/schema capability introspection.
     */

    if (options.input ==
        INPUT_SNAPSHOT_SCHEMA) {

        bool schema_json =
            options.output_explicit &&
            options.output == OUTPUT_JSON;

        if (options.pid_count != 0U ||
            options.section_explicit ||
            (options.output_explicit &&
             options.output != OUTPUT_JSON)) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (schema_json) {

            render_snapshot_schema_json();

        } else {

            render_snapshot_schema();
        }

        return 0;
    }

    /*
     * Snapshot compatibility diagnostics.
     */

    if (options.input ==
        INPUT_SNAPSHOT_COMPAT) {

        bool snapshot_json =
            options.output_explicit &&
            options.output == OUTPUT_JSON;

        if (options.pid_count != 0U ||
            options.section_explicit ||
            (options.output_explicit &&
             options.output != OUTPUT_JSON)) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (process_snapshot_probe(
                options.inspect_path,
                &compat_report,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            if (snapshot_json) {

                render_snapshot_compatibility_json(
                    options.inspect_path,
                    NULL,
                    error_buf
                );

            } else {

                fprintf(
                    stderr,
                    "nsdiff: %s: %s\n",
                    options.inspect_path,
                    error_buf
                );
            }

            return 2;
        }

        if (snapshot_json) {

            render_snapshot_compatibility_json(
                options.inspect_path,
                &compat_report,
                NULL
            );

        } else {

            render_snapshot_compatibility(
                options.inspect_path,
                &compat_report
            );
        }

        return compat_report.compatible
            ? 0
            : 2;
    }

    /*
     * Snapshot metadata / verification.
     */

    if (options.input ==
            INPUT_SNAPSHOT_INFO ||
        options.input ==
            INPUT_SNAPSHOT_VERIFY) {

        bool snapshot_json =
            options.output_explicit &&
            options.output == OUTPUT_JSON;

        if (options.pid_count != 0U ||
            options.section_explicit ||
            (options.output_explicit &&
             options.output != OUTPUT_JSON)) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (process_snapshot_inspect(
                options.inspect_path,
                &metadata,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            if (snapshot_json) {

                if (options.input ==
                    INPUT_SNAPSHOT_INFO) {

                    render_snapshot_metadata_json(
                        options.inspect_path,
                        NULL,
                        error_buf
                    );

                } else {

                    render_snapshot_verification_json(
                        options.inspect_path,
                        false,
                        error_buf
                    );
                }

            } else {

                fprintf(
                    stderr,
                    "nsdiff: %s: %s\n",
                    options.inspect_path,
                    error_buf
                );
            }

            return 2;
        }

        if (options.input ==
            INPUT_SNAPSHOT_INFO) {

            if (snapshot_json) {

                render_snapshot_metadata_json(
                    options.inspect_path,
                    &metadata,
                    NULL
                );

            } else {

                render_snapshot_metadata(
                    options.inspect_path,
                    &metadata
                );
            }

        } else {

            if (snapshot_json) {

                render_snapshot_verification_json(
                    options.inspect_path,
                    true,
                    NULL
                );

            } else {

                printf(
                    "nsdiff: snapshot OK: %s\n",
                    options.inspect_path
                );
            }
        }

        return 0;
    }

    /*
     * Portable diagnostic JSON export.
     *
     * Reuse the stable comparison JSON renderer by comparing
     * the saved snapshot with itself. This preserves the
     * existing schema and redaction behavior.
     */

    if (options.input ==
        INPUT_SNAPSHOT_EXPORT_JSON) {

        if (options.pid_count != 0U) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (process_snapshot_load(
                options.export_path,
                &a,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: %s: %s\n",
                options.export_path,
                error_buf
            );

            goto out;
        }

        process_diff_build(
            &a,
            &a,
            &diff
        );

        render_json_diff(
            &a,
            &a,
            &diff
        );

        rc = 0;

        goto out;
    }

    /*
     * Load/collect A and B.
     */

    switch (options.input) {

    case INPUT_LIVE_LIVE:

        if (options.pid_count != 2U) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (collect_live(
                options.pid_text[0],
                &a,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: A: %s\n",
                error_buf
            );

            goto out;
        }

        if (collect_live(
                options.pid_text[1],
                &b,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: B: %s\n",
                error_buf
            );

            goto out;
        }

        break;

    case INPUT_AGAINST_SNAPSHOT:

        if (options.pid_count != 1U) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (process_snapshot_load(
                options.snapshot_a_path,
                &a,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: %s: %s\n",
                options.snapshot_a_path,
                error_buf
            );

            goto out;
        }

        if (collect_live(
                options.pid_text[0],
                &b,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: B: %s\n",
                error_buf
            );

            goto out;
        }

        break;

    case INPUT_SNAPSHOT_SNAPSHOT:

        if (options.pid_count != 0U) {

            usage(
                stderr,
                argv[0]
            );

            return 2;
        }

        if (strcmp(
                options.snapshot_a_path,
                "-"
            ) == 0 &&
            strcmp(
                options.snapshot_b_path,
                "-"
            ) == 0) {

            fprintf(
                stderr,
                "nsdiff: --snapshots cannot read both snapshots from stdin\n"
            );

            return 2;
        }

        if (process_snapshot_load(
                options.snapshot_a_path,
                &a,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: %s: %s\n",
                options.snapshot_a_path,
                error_buf
            );

            goto out;
        }

        if (process_snapshot_load(
                options.snapshot_b_path,
                &b,
                error_buf,
                sizeof(error_buf)
            ) != 0) {

            fprintf(
                stderr,
                "nsdiff: %s: %s\n",
                options.snapshot_b_path,
                error_buf
            );

            goto out;
        }

        break;

    case INPUT_CONVERT:
    case INPUT_SEMANTIC_ID:
    case INPUT_CAPTURE:

        /*
         * Handled above.
         */

        break;

    case INPUT_SNAPSHOT_INFO:

        /*
         * Handled before comparison.
         */

        break;

    case INPUT_SNAPSHOT_VERIFY:

        /*
         * Handled before comparison.
         */

        break;

    case INPUT_SNAPSHOT_COMPAT:

        /*
         * Handled before comparison.
         */

        break;

    case INPUT_SNAPSHOT_MANIFEST:

        /*
         * Handled before comparison.
         */

        break;

    case INPUT_SNAPSHOT_ID:

        /*
         * Handled before comparison.
         */

        break;

    case INPUT_SNAPSHOT_SCHEMA:

        /*
         * Handled before comparison.
         */

        break;

    case INPUT_SNAPSHOT_EXPORT_JSON:

        /*
         * Handled before comparison.
         */

        break;
    }

    process_diff_build(
        &a,
        &b,
        &diff
    );

    active_diff =
        &diff;

    if (options.section_explicit) {

        process_diff_apply_scope(
            &diff,
            options.sections,
            &scoped_diff
        );

        active_diff =
            &scoped_diff;
    }


    switch (options.output) {

    case OUTPUT_TEXT:

        render_text_diff(
            &a,
            &b,
            &diff
        );

        break;

    case OUTPUT_JSON:

        render_json_diff(
            &a,
            &b,
            &diff
        );

        break;

    case OUTPUT_COMPACT:

        render_compact_diff(
            &a,
            &b,
            active_diff,
            false
        );

        break;

    case OUTPUT_EXPLAIN:

        render_compact_diff(
            &a,
            &b,
            active_diff,
            true
        );

        break;

    case OUTPUT_SUMMARY:

        process_diff_summary_build_scoped(
            &diff,
            options.sections,
            &summary
        );

        render_summary_scoped(
            &a,
            &b,
            &summary,
            options.sections
        );

        break;

    case OUTPUT_QUIET:

        break;
    }

    rc =
        active_diff->differences == 0U
            ? 0
            : 1;

out:
    process_snapshot_destroy(
        &a
    );

    process_snapshot_destroy(
        &b
    );

    return rc;
}

int main(int argc, char **argv)
{
    int rc = run_cli(argc, argv);
    if (fflush(stdout) || ferror(stdout)) {
        fprintf(stderr, "nsdiff: cannot finish writing stdout\n");
        return 2;
    }
    return rc;
}

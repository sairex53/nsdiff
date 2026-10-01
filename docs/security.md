# Security and collection limitations

Snapshots are untrusted input. Bounds, types, fixed item identities, bool object
representations, string termination, enum ranges, redaction policy and hashes are
validated before values reach the diff engine or renderers. Portable JSON uses
Jansson >=2.13 with duplicate rejection and a bounded lexical preflight. Errors do
not quote input field contents. No external reference or URL is fetched.

Native and portable files contain raw watched environment values, including proxy
credentials. Diagnostic views redact proxy values, but may still expose other
private paths/values. All snapshot content and IDs should be treated as private.
Redaction is enforced on import; malformed files cannot turn off proxy redaction.
SHA-256 and FNV detect corruption, not malicious forgery or authenticity. Native
metadata is outside the payload digest. Portable v1 has no stored checksum.

Files are written to a randomized adjacent O_EXCL/O_NOFOLLOW file, fchmod 0600,
written completely with EINTR handling, fsynced, closed, atomically renamed and the
opened parent directory fsynced. The same dirfd anchors create/rename/unlink/sync.
An existing destination symlink is replaced as a directory entry; its target is
untouched. Symlinks in the selected parent path are resolved while opening it;
use a directory you control. A directory-sync failure returns 2 even though the
new destination already exists. On ordinary failure the temporary file is removed.
SIGKILL, a fatal signal or power loss can leave a private randomized `.tmp.*` file;
no unsafe signal-handler cleanup is installed. SIGPIPE is converted to an I/O error.

`/proc` access is governed by normal permissions, hidepid, ptrace policies, user
namespaces, LSMs and kernel features. Root is not required. Do not run as root merely
to inspect a process you do not trust: target root/mount paths can refer to unusual
filesystems. Live reads are not a transactional kernel snapshot. Starttime is checked
before and after collection; pidfd readiness detects exit/reuse, including an exit
before the first identity read. If pidfd is unavailable or blocked, starttime checks
are the fallback and very fast reuse within one clock tick is a residual limitation.
An exec, credential change, remount, route update or environment change can occur
within one process lifetime. Snapshot data can consequently span multiple instants.

Collectors are intentionally bounded. Overlong watched env values, network overflow
and overlong mount data are `truncated` and excluded from comparison. Malformed/
ambiguous data is unavailable, not silently equal. Proc text lines are bounded to
64 KiB, environment reads to 8 MiB. libmount owns mount-table parsing/allocation:
large real mount tables scale with the kernel input; there is no universal fixed
mount-table cap. Cgroup files assume a conventional cgroup v2 mount visible at
`/sys/fs/cgroup` in the target root. Nonstandard layouts and `/../` paths can be
unavailable; cgroup v1 controller comparison is not implemented.

Human output is intended for terminal diagnostics, not a machine parser. Some
legacy non-environment descriptive values retain raw terminal bytes; for untrusted
process names/paths prefer the escaped JSON outputs. Reporting is read-only; no
privileged helper, setns, network service, telemetry or automatic upload exists.

Fuzz smoke is a limited regression check, not proof of absence of vulnerabilities.
System Jansson/libmount/libcap remain distro dependencies and should receive normal
security updates. CI and additional Linux live checks are required before tagging.

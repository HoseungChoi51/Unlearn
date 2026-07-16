#define _GNU_SOURCE

/*
 * One-reviewed-program Bash supervisor canary.
 *
 * This is deliberately not a general command API and not an authorization
 * boundary.  It consumes exactly one CBDSBRQ2 request, validates a reviewed
 * program through descriptor 3 and the fixed /cbds-program.sh path, validates
 * descriptor 4 as the exact 32-byte fixture-definition identity token, and
 * writes a deterministic post-run output-projection archive to descriptor 5.
 * The only argv it can execute is:
 *
 *   /usr/bin/bash --noprofile --norc /proc/self/fd/3
 *
 * Descriptor 3 must be either sealed or opened through a read-only mount;
 * /cbds-program.sh is independently checked as the projected-path copy.  The
 * child receives a fixed seccomp deny policy for network, namespace creation,
 * privilege changes, kernel administration, and other clearly dangerous
 * surfaces.  The outer launcher has a larger file-size limit so Bubblewrap can
 * project the pinned runtime; immediately before exec this supervisor lowers
 * the reviewed child to a 1 MiB RLIMIT_FSIZE.  It is intentionally not
 * evidence for arbitrary candidates,
 * runtime-data closure, exact-tool enforcement, a general Bash policy, scored
 * evaluation, model selection, or claim authority.
 *
 * Workspace output-projection format (little endian), version 1:
 *
 *   header:  magic[8]="CBDSWSN1", u32 version, u32 entry_count
 *   entry:   u8 type, zero[3], u32 mode, u32 path_bytes,
 *            u64 payload_bytes, path[path_bytes], payload[payload_bytes]
 *
 * Entries are pre-order, with raw directory-entry names sorted bytewise.
 * Type 1 is a directory (empty payload), type 2 is a regular file (payload is
 * its complete contents), and type 3 is a symlink (payload is its raw target).
 * The root entry has an empty path.  The exact top-level ``input`` entry and
 * its complete subtree are deliberately omitted: the trusted controller
 * independently rechecks the full descriptor-bound input baseline after
 * cgroup quiescence, while unprivileged PID1 cannot read mode-000 fixture
 * payloads.  Every other top-level entry is serialized.  Unsupported objects
 * outside ``input`` fail closed.  At most cap+1 bytes are materialized and
 * written; a partial archive is non-authoritative and is marked overflow.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REQUEST_BYTES 384U
#define RESULT_BYTES 512U
#define RESULT_HASHED_PREFIX_BYTES 480U
#if !defined(__x86_64__)
#error "the reviewed Bash seccomp policy is pinned to x86-64"
#endif

#define PROTOCOL_VERSION 2U

#define PROGRAM_FD 3
#define FIXTURE_IDENTITY_FD 4
#define WORKSPACE_SNAPSHOT_FD 5

#define MAX_PROGRAM_BYTES (64U * 1024U)
#define MAX_STREAM_CAP_BYTES (1024U * 1024U)
#define MAX_WORKSPACE_SNAPSHOT_BYTES (64U * 1024U * 1024U)
#define MIN_WALL_TIMEOUT_USEC 10000ULL
#define MAX_WALL_TIMEOUT_USEC 3600000000ULL
#define MIN_CPU_TIME_USEC 1000ULL
#define MAX_CPU_TIME_USEC 3600000000ULL
#define CAPTURE_BLOCK_BYTES 4096U
#define CLEANUP_TIMEOUT_USEC 1000000ULL
#define SNAPSHOT_MAX_DEPTH 64U
#define SNAPSHOT_MAX_ENTRIES 4096U
#define SNAPSHOT_MAX_PATH_BYTES 4096U
#define SNAPSHOT_MAX_REGULAR_BYTES (1024U * 1024U)
#define SNAPSHOT_MAX_TOTAL_PAYLOAD_BYTES (16U * 1024U * 1024U)
#define SNAPSHOT_MAX_SYMLINK_TARGET_BYTES 4096U
#define CHILD_FSIZE_MAX_BYTES (1024U * 1024U)

#define REQUEST_OFFSET_VERSION 8U
#define REQUEST_OFFSET_RESERVED_U32 12U
#define REQUEST_OFFSET_PROGRAM_BYTES 16U
#define REQUEST_OFFSET_WALL_TIMEOUT_USEC 24U
#define REQUEST_OFFSET_CPU_TIME_LIMIT_USEC 32U
#define REQUEST_OFFSET_STDOUT_CAP_BYTES 40U
#define REQUEST_OFFSET_STDERR_CAP_BYTES 48U
#define REQUEST_OFFSET_WORKSPACE_SNAPSHOT_CAP_BYTES 56U
#define REQUEST_OFFSET_NONCE 64U
#define REQUEST_OFFSET_INVOCATION_SHA256 96U
#define REQUEST_OFFSET_PROGRAM_SHA256 128U
#define REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256 160U
#define REQUEST_OFFSET_WORKSPACE_BASELINE_SHA256 192U
#define REQUEST_OFFSET_RUNTIME_SNAPSHOT_SHA256 224U
#define REQUEST_OFFSET_ALLOWED_TOOLS_SHA256 256U
#define REQUEST_OFFSET_POLICY_SHA256 288U
#define REQUEST_OFFSET_RESERVED 320U

#define RESULT_OFFSET_VERSION 8U
#define RESULT_OFFSET_OUTCOME 12U
#define RESULT_OFFSET_PROCESS_STATUS 16U
#define RESULT_OFFSET_CHILD_EXIT_CODE 20U
#define RESULT_OFFSET_CHILD_SIGNAL 24U
#define RESULT_OFFSET_FLAGS 28U
#define RESULT_OFFSET_STDOUT_OBSERVED 32U
#define RESULT_OFFSET_STDERR_OBSERVED 40U
#define RESULT_OFFSET_WAIT4_USER_CPU_USEC 48U
#define RESULT_OFFSET_WAIT4_SYS_CPU_USEC 56U
#define RESULT_OFFSET_WALL_USEC 64U
#define RESULT_OFFSET_DESCENDANTS_REAPED 72U
#define RESULT_OFFSET_RESERVED_U32 76U
#define RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES 80U
#define RESULT_OFFSET_CUMULATIVE_CPU_USEC 88U
#define RESULT_OFFSET_REQUEST_SHA256 96U
#define RESULT_OFFSET_NONCE 128U
#define RESULT_OFFSET_INVOCATION_SHA256 160U
#define RESULT_OFFSET_PROGRAM_SHA256 192U
#define RESULT_OFFSET_FIXTURE_DEFINITION_SHA256 224U
#define RESULT_OFFSET_WORKSPACE_BASELINE_SHA256 256U
#define RESULT_OFFSET_RUNTIME_SNAPSHOT_SHA256 288U
#define RESULT_OFFSET_ALLOWED_TOOLS_SHA256 320U
#define RESULT_OFFSET_POLICY_SHA256 352U
#define RESULT_OFFSET_STDOUT_SHA256 384U
#define RESULT_OFFSET_STDERR_SHA256 416U
#define RESULT_OFFSET_WORKSPACE_SNAPSHOT_SHA256 448U
#define RESULT_OFFSET_RESULT_SHA256 480U

static const unsigned char REQUEST_MAGIC[8] = {
    'C', 'B', 'D', 'S', 'B', 'R', 'Q', '2'
};
static const unsigned char RESULT_MAGIC[8] = {
    'C', 'B', 'D', 'S', 'B', 'R', 'S', '2'
};
static const unsigned char SNAPSHOT_MAGIC[8] = {
    'C', 'B', 'D', 'S', 'W', 'S', 'N', '1'
};

/* The sole source-reviewed case admitted by this canary. */
static const unsigned char REVIEWED_PROGRAM[] =
    "set -euo pipefail\n"
    "umask 022\n"
    "export LC_ALL=C\n"
    "mkdir -p -- output\n"
    "find input/tree -type f -perm /0444 -name '*.txt' "
    "-printf '%P\\n' | sort > output/paths.txt";
static const unsigned char REVIEWED_PROGRAM_SHA256[32] = {
    0x53U, 0x5aU, 0xd0U, 0x0bU, 0x0aU, 0xecU, 0x61U, 0x09U,
    0xc1U, 0x4bU, 0x9cU, 0x66U, 0xe3U, 0xc1U, 0x3bU, 0xa6U,
    0x94U, 0x81U, 0x8cU, 0xdfU, 0xb9U, 0xb7U, 0xa9U, 0x2fU,
    0x7cU, 0x72U, 0xf1U, 0x57U, 0x0cU, 0xd6U, 0x7eU, 0xf3U
};
static const unsigned char REVIEWED_INVOCATION_SHA256[32] = {
    0x37U, 0x38U, 0x15U, 0xddU, 0xe8U, 0x2cU, 0x7eU, 0xafU,
    0xc1U, 0xe4U, 0x79U, 0x6cU, 0x32U, 0x0cU, 0x04U, 0xd9U,
    0x3cU, 0x1fU, 0x30U, 0x20U, 0x9cU, 0x13U, 0x50U, 0xe8U,
    0x27U, 0xe6U, 0xd3U, 0xbcU, 0x85U, 0xe9U, 0x4aU, 0x94U
};
static const unsigned char REVIEWED_FIXTURE_DEFINITION_SHA256[32] = {
    0xa8U, 0x55U, 0x34U, 0x99U, 0x0eU, 0xadU, 0x9fU, 0x2cU,
    0x06U, 0xe6U, 0xa6U, 0x44U, 0x24U, 0xabU, 0xf4U, 0xdaU,
    0x90U, 0xd0U, 0x1dU, 0xcbU, 0x59U, 0xb2U, 0x90U, 0xc6U,
    0x9aU, 0xf1U, 0x58U, 0x27U, 0x56U, 0x86U, 0x85U, 0xa9U
};

enum outcome_id {
    OUTCOME_NORMAL = 1,
    OUTCOME_NONZERO = 2,
    OUTCOME_SIGNAL = 3,
    OUTCOME_WALL_TIMEOUT = 4,
    OUTCOME_CPU_LIMIT = 5,
    OUTCOME_STDOUT_OVERFLOW = 6,
    OUTCOME_STDERR_OVERFLOW = 7,
    OUTCOME_WORKSPACE_SNAPSHOT_OVERFLOW = 8,
    OUTCOME_SUPERVISOR_ERROR = 9
};

enum process_status_id {
    PROCESS_NOT_REAPED = 0,
    PROCESS_EXITED = 1,
    PROCESS_SIGNALED = 2
};

enum result_flags {
    FLAG_REQUEST_VALIDATED = 1U << 0,
    FLAG_PROGRAM_DESCRIPTOR_VALIDATED = 1U << 1,
    FLAG_FIXTURE_DESCRIPTOR_VALIDATED = 1U << 2,
    FLAG_RUNTIME_SNAPSHOT_VALIDATED = 1U << 3,
    FLAG_WORKSPACE_BASELINE_VALIDATED = 1U << 4,
    FLAG_ALLOWED_TOOLS_VALIDATED = 1U << 5,
    FLAG_POLICY_VALIDATED = 1U << 6,
    FLAG_CHILD_NO_NEW_PRIVS = 1U << 7,
    FLAG_CHILD_PREEXEC_DUMPABLE_DISABLED = 1U << 8,
    FLAG_CHILD_SECCOMP_INSTALLED = 1U << 9,
    FLAG_PRIMARY_REAPED = 1U << 10,
    FLAG_ALL_DESCENDANTS_REAPED = 1U << 11,
    FLAG_SOLE_PID1 = 1U << 12,
    FLAG_STDOUT_OVERFLOW = 1U << 13,
    FLAG_STDERR_OVERFLOW = 1U << 14,
    FLAG_WALL_LIMIT_REACHED = 1U << 15,
    FLAG_CPU_LIMIT_REACHED = 1U << 16,
    FLAG_WORKSPACE_SNAPSHOT_WRITTEN = 1U << 17,
    FLAG_WORKSPACE_SNAPSHOT_OVERFLOW = 1U << 18
};

enum snapshot_type {
    SNAPSHOT_DIRECTORY = 1,
    SNAPSHOT_REGULAR = 2,
    SNAPSHOT_SYMLINK = 3
};

struct request {
    uint64_t program_bytes;
    uint64_t wall_timeout_usec;
    uint64_t cpu_time_limit_usec;
    uint64_t stdout_cap_bytes;
    uint64_t stderr_cap_bytes;
    uint64_t workspace_snapshot_cap_bytes;
    unsigned char encoded[REQUEST_BYTES];
};

struct sha256_context {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char block[64];
    size_t block_used;
};

struct capture_state {
    struct sha256_context digest;
    uint64_t observed;
    uint64_t cap;
    int descriptor;
    int open;
    int overflow;
};

struct supervisor_state {
    pid_t primary_pid;
    int primary_reaped;
    int primary_wait_status;
    int all_reaped;
    uint32_t descendants_reaped;
    uint64_t user_cpu_usec;
    uint64_t sys_cpu_usec;
};

struct snapshot_buffer {
    unsigned char *bytes;
    size_t used;
    size_t ceiling;
    uint32_t entries;
    uint64_t total_payload_bytes;
    int overflow;
};

struct name_list {
    char **items;
    size_t count;
    size_t capacity;
};

static volatile sig_atomic_t termination_signal_received = 0;

static uint32_t rotate_right(uint32_t value, unsigned int amount) {
    return (value >> amount) | (value << (32U - amount));
}

static uint32_t load_be32(const unsigned char *source) {
    return ((uint32_t)source[0] << 24) |
           ((uint32_t)source[1] << 16) |
           ((uint32_t)source[2] << 8) |
           (uint32_t)source[3];
}

static uint32_t load_le32(const unsigned char *source) {
    return (uint32_t)source[0] |
           ((uint32_t)source[1] << 8) |
           ((uint32_t)source[2] << 16) |
           ((uint32_t)source[3] << 24);
}

static uint64_t load_le64(const unsigned char *source) {
    uint64_t value = 0U;
    unsigned int index;
    for (index = 0U; index < 8U; ++index) {
        value |= (uint64_t)source[index] << (index * 8U);
    }
    return value;
}

static void store_be32(unsigned char *destination, uint32_t value) {
    destination[0] = (unsigned char)(value >> 24);
    destination[1] = (unsigned char)(value >> 16);
    destination[2] = (unsigned char)(value >> 8);
    destination[3] = (unsigned char)value;
}

static void store_le32(unsigned char *destination, uint32_t value) {
    destination[0] = (unsigned char)value;
    destination[1] = (unsigned char)(value >> 8);
    destination[2] = (unsigned char)(value >> 16);
    destination[3] = (unsigned char)(value >> 24);
}

static void store_le64(unsigned char *destination, uint64_t value) {
    unsigned int index;
    for (index = 0U; index < 8U; ++index) {
        destination[index] = (unsigned char)(value >> (index * 8U));
    }
}

static const uint32_t sha256_round_constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void sha256_transform(struct sha256_context *context,
                             const unsigned char block[64]) {
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned int index;

    for (index = 0U; index < 16U; ++index) {
        words[index] = load_be32(block + index * 4U);
    }
    for (index = 16U; index < 64U; ++index) {
        uint32_t s0 = rotate_right(words[index - 15U], 7U) ^
                      rotate_right(words[index - 15U], 18U) ^
                      (words[index - 15U] >> 3U);
        uint32_t s1 = rotate_right(words[index - 2U], 17U) ^
                      rotate_right(words[index - 2U], 19U) ^
                      (words[index - 2U] >> 10U);
        words[index] = words[index - 16U] + s0 +
                       words[index - 7U] + s1;
    }

    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];
    for (index = 0U; index < 64U; ++index) {
        uint32_t sigma1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^
                          rotate_right(e, 25U);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t first = h + sigma1 + choose +
                         sha256_round_constants[index] + words[index];
        uint32_t sigma0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^
                          rotate_right(a, 22U);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t second = sigma0 + majority;
        h = g; g = f; f = e; e = d + first;
        d = c; c = b; b = a; a = first + second;
    }
    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static void sha256_init(struct sha256_context *context) {
    static const uint32_t initial[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    memcpy(context->state, initial, sizeof(initial));
    context->bit_count = 0U;
    context->block_used = 0U;
}

static void sha256_update(struct sha256_context *context,
                          const unsigned char *data, size_t size) {
    while (size > 0U) {
        size_t space = sizeof(context->block) - context->block_used;
        size_t amount = size < space ? size : space;
        memcpy(context->block + context->block_used, data, amount);
        context->block_used += amount;
        context->bit_count += (uint64_t)amount * 8U;
        data += amount;
        size -= amount;
        if (context->block_used == sizeof(context->block)) {
            sha256_transform(context, context->block);
            context->block_used = 0U;
        }
    }
}

static void sha256_final(struct sha256_context *context,
                         unsigned char digest[32]) {
    uint64_t original_bits = context->bit_count;
    unsigned int index;
    context->block[context->block_used++] = 0x80U;
    if (context->block_used > 56U) {
        while (context->block_used < 64U) {
            context->block[context->block_used++] = 0U;
        }
        sha256_transform(context, context->block);
        context->block_used = 0U;
    }
    while (context->block_used < 56U) {
        context->block[context->block_used++] = 0U;
    }
    for (index = 0U; index < 8U; ++index) {
        context->block[63U - index] =
            (unsigned char)(original_bits >> (index * 8U));
    }
    sha256_transform(context, context->block);
    for (index = 0U; index < 8U; ++index) {
        store_be32(digest + index * 4U, context->state[index]);
    }
    memset(context, 0, sizeof(*context));
}

static void sha256_bytes(const unsigned char *data, size_t size,
                         unsigned char digest[32]) {
    struct sha256_context context;
    sha256_init(&context);
    sha256_update(&context, data, size);
    sha256_final(&context, digest);
}

static int is_nonzero_digest(const unsigned char *digest) {
    unsigned int index;
    unsigned char combined = 0U;
    for (index = 0U; index < 32U; ++index) {
        combined |= digest[index];
    }
    return combined != 0U;
}

static int read_exact_stdin(unsigned char destination[REQUEST_BYTES]) {
    size_t used = 0U;
    while (used < REQUEST_BYTES) {
        ssize_t amount = read(STDIN_FILENO, destination + used,
                              REQUEST_BYTES - used);
        if (amount > 0) {
            used += (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    for (;;) {
        unsigned char extra;
        ssize_t amount = read(STDIN_FILENO, &extra, 1U);
        if (amount == 0) {
            return 0;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
}

static int parse_request(struct request *request) {
    unsigned int offset;
    if (read_exact_stdin(request->encoded) != 0 ||
        memcmp(request->encoded, REQUEST_MAGIC, sizeof(REQUEST_MAGIC)) != 0 ||
        load_le32(request->encoded + REQUEST_OFFSET_VERSION) !=
            PROTOCOL_VERSION ||
        load_le32(request->encoded + REQUEST_OFFSET_RESERVED_U32) != 0U) {
        return -1;
    }
    for (offset = REQUEST_OFFSET_RESERVED; offset < REQUEST_BYTES; ++offset) {
        if (request->encoded[offset] != 0U) {
            return -1;
        }
    }
    request->program_bytes = load_le64(
        request->encoded + REQUEST_OFFSET_PROGRAM_BYTES);
    request->wall_timeout_usec = load_le64(
        request->encoded + REQUEST_OFFSET_WALL_TIMEOUT_USEC);
    request->cpu_time_limit_usec = load_le64(
        request->encoded + REQUEST_OFFSET_CPU_TIME_LIMIT_USEC);
    request->stdout_cap_bytes = load_le64(
        request->encoded + REQUEST_OFFSET_STDOUT_CAP_BYTES);
    request->stderr_cap_bytes = load_le64(
        request->encoded + REQUEST_OFFSET_STDERR_CAP_BYTES);
    request->workspace_snapshot_cap_bytes = load_le64(
        request->encoded + REQUEST_OFFSET_WORKSPACE_SNAPSHOT_CAP_BYTES);
    if (request->program_bytes == 0U ||
        request->program_bytes > MAX_PROGRAM_BYTES ||
        request->wall_timeout_usec < MIN_WALL_TIMEOUT_USEC ||
        request->wall_timeout_usec > MAX_WALL_TIMEOUT_USEC ||
        request->cpu_time_limit_usec < MIN_CPU_TIME_USEC ||
        request->cpu_time_limit_usec > MAX_CPU_TIME_USEC ||
        request->stdout_cap_bytes == 0U ||
        request->stdout_cap_bytes > MAX_STREAM_CAP_BYTES ||
        request->stderr_cap_bytes == 0U ||
        request->stderr_cap_bytes > MAX_STREAM_CAP_BYTES ||
        request->workspace_snapshot_cap_bytes == 0U ||
        request->workspace_snapshot_cap_bytes >
            MAX_WORKSPACE_SNAPSHOT_BYTES) {
        return -1;
    }
    for (offset = REQUEST_OFFSET_NONCE;
         offset <= REQUEST_OFFSET_POLICY_SHA256; offset += 32U) {
        if (!is_nonzero_digest(request->encoded + offset)) {
            return -1;
        }
    }
    if (request->program_bytes != sizeof(REVIEWED_PROGRAM) - 1U ||
        memcmp(request->encoded + REQUEST_OFFSET_PROGRAM_SHA256,
               REVIEWED_PROGRAM_SHA256, 32U) != 0 ||
        memcmp(request->encoded + REQUEST_OFFSET_INVOCATION_SHA256,
               REVIEWED_INVOCATION_SHA256, 32U) != 0 ||
        memcmp(request->encoded + REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256,
               REVIEWED_FIXTURE_DEFINITION_SHA256, 32U) != 0) {
        return -1;
    }
    return 0;
}

static int descriptor_is_read_only_regular(int descriptor, uint64_t size) {
    struct stat status;
    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < 0 || (uint64_t)status.st_size != size) {
        return 0;
    }
    return 1;
}

static int descriptor_content_is_immutable(int descriptor) {
    struct statvfs filesystem;
#ifdef F_GET_SEALS
    int seals = fcntl(descriptor, F_GET_SEALS);
    if (seals >= 0 &&
        (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) ==
            (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) {
        return 1;
    }
#endif
    if (fstatvfs(descriptor, &filesystem) == 0 &&
        (filesystem.f_flag & ST_RDONLY) != 0U) {
        return 1;
    }
    return 0;
}

static int pread_exact(int descriptor, unsigned char *destination,
                       size_t size) {
    size_t used = 0U;
    while (used < size) {
        ssize_t amount = pread(descriptor, destination + used, size - used,
                               (off_t)used);
        if (amount > 0) {
            used += (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int validate_program_descriptor(const struct request *request) {
    unsigned char *program;
    unsigned char digest[32];
    int path_descriptor = -1;
    struct stat path_status;
    int valid = 0;

    if (!descriptor_is_read_only_regular(PROGRAM_FD,
                                         request->program_bytes) ||
        !descriptor_content_is_immutable(PROGRAM_FD)) {
        return 0;
    }
    program = malloc((size_t)request->program_bytes);
    if (program == NULL) {
        return 0;
    }
    if (pread_exact(PROGRAM_FD, program, (size_t)request->program_bytes) != 0) {
        goto done;
    }
    if (memcmp(program, REVIEWED_PROGRAM, sizeof(REVIEWED_PROGRAM) - 1U) != 0) {
        goto done;
    }
    sha256_bytes(program, (size_t)request->program_bytes, digest);
    if (memcmp(digest,
               request->encoded + REQUEST_OFFSET_PROGRAM_SHA256, 32U) != 0) {
        goto done;
    }
    path_descriptor = open("/cbds-program.sh",
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (path_descriptor < 0 ||
        !descriptor_content_is_immutable(path_descriptor) ||
        fstat(path_descriptor, &path_status) != 0 ||
        !S_ISREG(path_status.st_mode) || path_status.st_size < 0 ||
        (uint64_t)path_status.st_size != request->program_bytes ||
        pread_exact(path_descriptor, program,
                    (size_t)request->program_bytes) != 0) {
        goto done;
    }
    if (memcmp(program, REVIEWED_PROGRAM, sizeof(REVIEWED_PROGRAM) - 1U) != 0) {
        goto done;
    }
    sha256_bytes(program, (size_t)request->program_bytes, digest);
    valid = memcmp(digest,
                   request->encoded + REQUEST_OFFSET_PROGRAM_SHA256,
                   32U) == 0;
done:
    if (path_descriptor >= 0) {
        (void)close(path_descriptor);
    }
    memset(program, 0, (size_t)request->program_bytes);
    free(program);
    return valid;
}

static int validate_fixture_identity_descriptor(const struct request *request) {
    unsigned char identity[32];
    if (!descriptor_is_read_only_regular(FIXTURE_IDENTITY_FD, 32U) ||
        !descriptor_content_is_immutable(FIXTURE_IDENTITY_FD) ||
        pread_exact(FIXTURE_IDENTITY_FD, identity, sizeof(identity)) != 0) {
        return 0;
    }
    return memcmp(identity,
                  request->encoded +
                      REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256,
                  sizeof(identity)) == 0;
}

static uint64_t monotonic_microseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0) {
        return 0U;
    }
    if ((uint64_t)value.tv_sec > UINT64_MAX / 1000000U) {
        return UINT64_MAX;
    }
    return (uint64_t)value.tv_sec * 1000000U +
           (uint64_t)value.tv_nsec / 1000U;
}

static uint64_t saturating_add(uint64_t left, uint64_t right) {
    return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static void termination_handler(int signal_number) {
    (void)signal_number;
    termination_signal_received = 1;
}

static int install_supervisor_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = termination_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0) {
        return -1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGPIPE, &action, NULL);
}

static int set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL, 0);
    return flags < 0 ||
           fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0 ? -1 : 0;
}

static int write_all(int descriptor, const unsigned char *data, size_t size) {
    while (size > 0U) {
        ssize_t amount = write(descriptor, data, size);
        if (amount > 0) {
            data += (size_t)amount;
            size -= (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

#define DENY_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | \
             ((uint32_t)EPERM & SECCOMP_RET_DATA))

#define ABSENT_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | \
             ((uint32_t)ENOSYS & SECCOMP_RET_DATA))

static int install_reviewed_bash_seccomp(void) {
    static const uint32_t forbidden_clone_flags =
        CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
        CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS | CLONE_PTRACE |
        CLONE_UNTRACED;
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),

        /* Bash may clone ordinary children, never namespaces/traced tasks. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, forbidden_clone_flags, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO |
                 ((uint32_t)EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),

#ifdef SYS_clone3
        /* Force libc to its ordinary clone fallback; clone3 flags are indirect. */
        ABSENT_SYSCALL(SYS_clone3),
#endif

        /* No network endpoint or message transport, including AF_UNIX. */
        DENY_SYSCALL(SYS_socket),
        DENY_SYSCALL(SYS_socketpair),
        DENY_SYSCALL(SYS_connect),
        DENY_SYSCALL(SYS_accept),
        DENY_SYSCALL(SYS_accept4),
        DENY_SYSCALL(SYS_bind),
        DENY_SYSCALL(SYS_listen),
        DENY_SYSCALL(SYS_sendto),
        DENY_SYSCALL(SYS_recvfrom),
        DENY_SYSCALL(SYS_sendmsg),
        DENY_SYSCALL(SYS_recvmsg),
        DENY_SYSCALL(SYS_shutdown),
        DENY_SYSCALL(SYS_getsockname),
        DENY_SYSCALL(SYS_getpeername),
        DENY_SYSCALL(SYS_setsockopt),
        DENY_SYSCALL(SYS_getsockopt),
#ifdef SYS_recvmmsg
        DENY_SYSCALL(SYS_recvmmsg),
#endif
#ifdef SYS_sendmmsg
        DENY_SYSCALL(SYS_sendmmsg),
#endif

        /* No namespace, mount, filesystem-server, or device administration. */
        DENY_SYSCALL(SYS_unshare),
        DENY_SYSCALL(SYS_setns),
        DENY_SYSCALL(SYS_mount),
        DENY_SYSCALL(SYS_umount2),
        DENY_SYSCALL(SYS_pivot_root),
        DENY_SYSCALL(SYS_chroot),
        DENY_SYSCALL(SYS_mknod),
        DENY_SYSCALL(SYS_mknodat),
        DENY_SYSCALL(SYS_swapon),
        DENY_SYSCALL(SYS_swapoff),
        DENY_SYSCALL(SYS_quotactl),
        DENY_SYSCALL(SYS_acct),
#ifdef SYS_open_tree
        DENY_SYSCALL(SYS_open_tree),
#endif
#ifdef SYS_move_mount
        DENY_SYSCALL(SYS_move_mount),
#endif
#ifdef SYS_fsopen
        DENY_SYSCALL(SYS_fsopen),
#endif
#ifdef SYS_fsconfig
        DENY_SYSCALL(SYS_fsconfig),
#endif
#ifdef SYS_fsmount
        DENY_SYSCALL(SYS_fsmount),
#endif
#ifdef SYS_fspick
        DENY_SYSCALL(SYS_fspick),
#endif
#ifdef SYS_mount_setattr
        DENY_SYSCALL(SYS_mount_setattr),
#endif
#ifdef SYS_open_by_handle_at
        DENY_SYSCALL(SYS_open_by_handle_at),
#endif
#ifdef SYS_name_to_handle_at
        DENY_SYSCALL(SYS_name_to_handle_at),
#endif
#ifdef SYS_fanotify_init
        DENY_SYSCALL(SYS_fanotify_init),
#endif
#ifdef SYS_fanotify_mark
        DENY_SYSCALL(SYS_fanotify_mark),
#endif

        /* No credentials, capabilities, host identity, or privileged clocks. */
        DENY_SYSCALL(SYS_setuid),
        DENY_SYSCALL(SYS_setgid),
        DENY_SYSCALL(SYS_setreuid),
        DENY_SYSCALL(SYS_setregid),
        DENY_SYSCALL(SYS_setresuid),
        DENY_SYSCALL(SYS_setresgid),
        DENY_SYSCALL(SYS_setfsuid),
        DENY_SYSCALL(SYS_setfsgid),
        DENY_SYSCALL(SYS_setgroups),
        DENY_SYSCALL(SYS_capset),
        DENY_SYSCALL(SYS_sethostname),
        DENY_SYSCALL(SYS_setdomainname),
        DENY_SYSCALL(SYS_settimeofday),
        DENY_SYSCALL(SYS_adjtimex),
        DENY_SYSCALL(SYS_clock_settime),
#ifdef SYS_clock_adjtime
        DENY_SYSCALL(SYS_clock_adjtime),
#endif

        /* No kernel extension, tracing, cross-process memory, or raw I/O. */
        DENY_SYSCALL(SYS_ptrace),
        DENY_SYSCALL(SYS_process_vm_readv),
        DENY_SYSCALL(SYS_process_vm_writev),
        DENY_SYSCALL(SYS_kcmp),
        DENY_SYSCALL(SYS_bpf),
        DENY_SYSCALL(SYS_perf_event_open),
        DENY_SYSCALL(SYS_userfaultfd),
        DENY_SYSCALL(SYS_add_key),
        DENY_SYSCALL(SYS_request_key),
        DENY_SYSCALL(SYS_keyctl),
        DENY_SYSCALL(SYS_init_module),
        DENY_SYSCALL(SYS_finit_module),
        DENY_SYSCALL(SYS_delete_module),
        DENY_SYSCALL(SYS_kexec_load),
#ifdef SYS_kexec_file_load
        DENY_SYSCALL(SYS_kexec_file_load),
#endif
        DENY_SYSCALL(SYS_reboot),
        DENY_SYSCALL(SYS_iopl),
        DENY_SYSCALL(SYS_ioperm),
        DENY_SYSCALL(SYS_syslog),
        DENY_SYSCALL(SYS_personality),
#ifdef SYS_pidfd_getfd
        DENY_SYSCALL(SYS_pidfd_getfd),
#endif
#ifdef SYS_pidfd_send_signal
        DENY_SYSCALL(SYS_pidfd_send_signal),
#endif
#ifdef SYS_process_madvise
        DENY_SYSCALL(SYS_process_madvise),
#endif
#ifdef SYS_process_mrelease
        DENY_SYSCALL(SYS_process_mrelease),
#endif
#ifdef SYS_io_uring_setup
        DENY_SYSCALL(SYS_io_uring_setup),
#endif
#ifdef SYS_io_uring_enter
        DENY_SYSCALL(SYS_io_uring_enter),
#endif
#ifdef SYS_io_uring_register
        DENY_SYSCALL(SYS_io_uring_register),
#endif
#ifdef SYS_memfd_create
        DENY_SYSCALL(SYS_memfd_create),
#endif
#ifdef SYS_execveat
        DENY_SYSCALL(SYS_execveat),
#endif

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program;
    program.len = (unsigned short)(sizeof(instructions) /
                                   sizeof(instructions[0]));
    program.filter = instructions;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static int install_reviewed_child_resource_limits(void) {
    const struct rlimit no_core = {0U, 0U};
    const struct rlimit file_size = {
        CHILD_FSIZE_MAX_BYTES,
        CHILD_FSIZE_MAX_BYTES
    };
    return setrlimit(RLIMIT_CORE, &no_core) != 0 ||
           setrlimit(RLIMIT_FSIZE, &file_size) != 0 ? -1 : 0;
}

static void reset_child_signals(void) {
    struct sigaction action;
    int number;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    for (number = 1; number < NSIG; ++number) {
        if (number != SIGKILL && number != SIGSTOP) {
            (void)sigaction(number, &action, NULL);
        }
    }
}

static void close_child_descriptors(int ready_descriptor) {
    long maximum = sysconf(_SC_OPEN_MAX);
    int descriptor;
    if (maximum < 0 || maximum > 65536L) {
        maximum = 65536L;
    }
    for (descriptor = 3; descriptor < (int)maximum; ++descriptor) {
        if (descriptor != PROGRAM_FD && descriptor != ready_descriptor) {
            (void)close(descriptor);
        }
    }
}

static void child_main(int stdout_write, int stderr_write, int ready_write,
                       int stdout_read, int stderr_read, int ready_read) {
    static char *const argv[] = {
        (char *)"/usr/bin/bash",
        (char *)"--noprofile",
        (char *)"--norc",
        (char *)"/proc/self/fd/3",
        NULL
    };
    static char *const environment[] = {
        (char *)"HOME=/nonexistent",
        (char *)"LANG=C",
        (char *)"LC_ALL=C",
        (char *)"PATH=/usr/bin:/bin",
        (char *)"SHELL=/usr/bin/bash",
        (char *)"TZ=UTC",
        NULL
    };
    static const unsigned char ready = 'R';
    int null_descriptor;

    (void)close(stdout_read);
    (void)close(stderr_read);
    (void)close(ready_read);
    null_descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_descriptor < 0 ||
        dup2(null_descriptor, STDIN_FILENO) < 0 ||
        dup2(stdout_write, STDOUT_FILENO) < 0 ||
        dup2(stderr_write, STDERR_FILENO) < 0) {
        _exit(120);
    }
    if (null_descriptor > STDERR_FILENO) {
        (void)close(null_descriptor);
    }
    if (ready_write != 6) {
        if (dup2(ready_write, 6) < 0) {
            _exit(121);
        }
        ready_write = 6;
    }
    close_child_descriptors(ready_write);
    if (lseek(PROGRAM_FD, 0, SEEK_SET) != 0 ||
        fcntl(PROGRAM_FD, F_SETFD, 0) != 0) {
        _exit(123);
    }
    reset_child_signals();
    (void)umask(077);
    if (chdir("/workspace") != 0 ||
        install_reviewed_child_resource_limits() != 0 ||
        prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0 ||
        install_reviewed_bash_seccomp() != 0 ||
        write_all(ready_write, &ready, 1U) != 0) {
        _exit(122);
    }
    (void)close(ready_write);
    execve("/usr/bin/bash", argv, environment);
    _exit(127);
}

static void add_rusage(struct supervisor_state *state,
                       const struct rusage *usage) {
    uint64_t user = (uint64_t)usage->ru_utime.tv_sec * 1000000U +
                    (uint64_t)usage->ru_utime.tv_usec;
    uint64_t system = (uint64_t)usage->ru_stime.tv_sec * 1000000U +
                      (uint64_t)usage->ru_stime.tv_usec;
    state->user_cpu_usec = saturating_add(state->user_cpu_usec, user);
    state->sys_cpu_usec = saturating_add(state->sys_cpu_usec, system);
}

static int reap_available(struct supervisor_state *state) {
    for (;;) {
        struct rusage usage;
        int wait_status = 0;
        pid_t reaped;
        memset(&usage, 0, sizeof(usage));
        reaped = wait4(-1, &wait_status, WNOHANG, &usage);
        if (reaped > 0) {
            if (state->descendants_reaped != UINT32_MAX) {
                ++state->descendants_reaped;
            }
            add_rusage(state, &usage);
            if (reaped == state->primary_pid) {
                state->primary_reaped = 1;
                state->primary_wait_status = wait_status;
            }
        } else if (reaped == 0) {
            return 0;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == ECHILD) {
            state->all_reaped = 1;
            return 0;
        } else {
            return -1;
        }
    }
}

static void kill_namespace_processes(void) {
    if (kill(-1, SIGKILL) != 0 && errno != ESRCH) {
        /* Sole-PID1 verification remains authoritative. */
    }
}

static int parse_proc_stat_ticks(const char *text, uint64_t *ticks) {
    const char *cursor = strrchr(text, ')');
    unsigned int field = 3U;
    uint64_t accounted_ticks = 0U;
    if (cursor == NULL || cursor[1] != ' ') {
        return -1;
    }
    cursor += 2;
    while (*cursor != '\0' && field <= 17U) {
        const char *start = cursor;
        const char *end;
        while (*cursor != '\0' && *cursor != ' ') {
            ++cursor;
        }
        end = cursor;
        if (field >= 14U && field <= 17U) {
            uint64_t value = 0U;
            const char *digit = start;
            if (digit == end) {
                return -1;
            }
            while (digit < end) {
                unsigned int number;
                if (*digit < '0' || *digit > '9') {
                    return -1;
                }
                number = (unsigned int)(*digit - '0');
                if (value > (UINT64_MAX - number) / 10U) {
                    return -1;
                }
                value = value * 10U + number;
                ++digit;
            }
            accounted_ticks = saturating_add(accounted_ticks, value);
        }
        while (*cursor == ' ') {
            ++cursor;
        }
        ++field;
    }
    if (field <= 17U) {
        return -1;
    }
    /* utime, stime, cutime, cstime: reaped grandchildren stay visible. */
    *ticks = accounted_ticks;
    return 0;
}

static int live_namespace_cpu_usec(uint64_t *microseconds) {
    DIR *directory = opendir("/proc");
    struct dirent *entry;
    uint64_t total_ticks = 0U;
    long ticks_per_second = sysconf(_SC_CLK_TCK);
    int valid = 1;
    if (directory == NULL || ticks_per_second <= 0) {
        if (directory != NULL) {
            (void)closedir(directory);
        }
        return -1;
    }
    for (;;) {
        char path[128];
        char buffer[4096];
        char *end = NULL;
        unsigned long process;
        int descriptor;
        int path_bytes;
        ssize_t amount;
        uint64_t ticks;

        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                valid = 0;
            }
            break;
        }
        errno = 0;
        process = strtoul(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' ||
            process == 1UL) {
            continue;
        }
        path_bytes = snprintf(path, sizeof(path), "/proc/%lu/stat", process);
        if (path_bytes < 0 || (size_t)path_bytes >= sizeof(path)) {
            valid = 0;
            break;
        }
        descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0) {
            if (errno == ENOENT) {
                continue;
            }
            valid = 0;
            break;
        }
        do {
            amount = read(descriptor, buffer, sizeof(buffer) - 1U);
        } while (amount < 0 && errno == EINTR);
        (void)close(descriptor);
        if (amount < 0) {
            if (errno == ENOENT || errno == ESRCH || errno == EIO) {
                continue;
            }
            valid = 0;
            break;
        }
        if (amount == 0) {
            /* The process exited between open and read; wait4 accounts it. */
            continue;
        }
        if ((size_t)amount == sizeof(buffer) - 1U) {
            valid = 0;
            break;
        }
        buffer[amount] = '\0';
        if (parse_proc_stat_ticks(buffer, &ticks) != 0) {
            /* A concurrently exiting procfs entry is transient, not trust. */
            continue;
        }
        total_ticks = saturating_add(total_ticks, ticks);
    }
    (void)closedir(directory);
    if (!valid) {
        return -1;
    }
    if (total_ticks > UINT64_MAX / 1000000U) {
        *microseconds = UINT64_MAX;
    } else {
        *microseconds = total_ticks * 1000000U /
                        (uint64_t)ticks_per_second;
    }
    return 0;
}

static int drain_capture(struct capture_state *capture) {
    unsigned char block[CAPTURE_BLOCK_BYTES];
    while (capture->open) {
        uint64_t ceiling = capture->cap + 1U;
        size_t remaining;
        ssize_t amount;
        if (capture->observed >= ceiling) {
            capture->overflow = 1;
            (void)close(capture->descriptor);
            capture->descriptor = -1;
            capture->open = 0;
            return 1;
        }
        remaining = (size_t)(ceiling - capture->observed);
        if (remaining > sizeof(block)) {
            remaining = sizeof(block);
        }
        amount = read(capture->descriptor, block, remaining);
        if (amount > 0) {
            sha256_update(&capture->digest, block, (size_t)amount);
            capture->observed += (uint64_t)amount;
            if (capture->observed == ceiling) {
                capture->overflow = 1;
                (void)close(capture->descriptor);
                capture->descriptor = -1;
                capture->open = 0;
                return 1;
            }
        } else if (amount == 0) {
            (void)close(capture->descriptor);
            capture->descriptor = -1;
            capture->open = 0;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        } else {
            return -1;
        }
    }
    return 0;
}

static int drain_ready(int *descriptor, int *open_state, int *ready_seen,
                       int *ready_invalid) {
    unsigned char block[2];
    while (*open_state) {
        ssize_t amount = read(*descriptor, block, sizeof(block));
        if (amount > 0) {
            if (amount != 1 || block[0] != 'R' || *ready_seen) {
                *ready_invalid = 1;
            } else {
                *ready_seen = 1;
            }
        } else if (amount == 0) {
            (void)close(*descriptor);
            *descriptor = -1;
            *open_state = 0;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        } else {
            return -1;
        }
    }
    return 0;
}

static int sole_namespace_pid1(void) {
    DIR *directory = opendir("/proc");
    struct dirent *entry;
    unsigned int count = 0U;
    int only_pid1 = 1;
    if (directory == NULL) {
        return 0;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        const unsigned char *text = (const unsigned char *)entry->d_name;
        size_t index = 0U;
        while (text[index] >= '0' && text[index] <= '9') {
            ++index;
        }
        if (index == 0U || text[index] != '\0') {
            continue;
        }
        ++count;
        if (!(index == 1U && text[0] == '1')) {
            only_pid1 = 0;
        }
    }
    if (errno != 0) {
        only_pid1 = 0;
    }
    (void)closedir(directory);
    return count == 1U && only_pid1;
}

static int snapshot_append(struct snapshot_buffer *snapshot,
                           const void *source, size_t size) {
    size_t remaining;
    size_t amount;
    if (snapshot->overflow) {
        return 1;
    }
    remaining = snapshot->ceiling - snapshot->used;
    amount = size < remaining ? size : remaining;
    if (amount > 0U) {
        memcpy(snapshot->bytes + snapshot->used, source, amount);
        snapshot->used += amount;
    }
    if (amount != size) {
        snapshot->overflow = 1;
        return 1;
    }
    return 0;
}

static int snapshot_force_overflow(struct snapshot_buffer *snapshot) {
    if (snapshot->used < snapshot->ceiling) {
        memset(snapshot->bytes + snapshot->used, 0,
               snapshot->ceiling - snapshot->used);
        snapshot->used = snapshot->ceiling;
    }
    snapshot->overflow = 1;
    return 1;
}

static int snapshot_append_u32(struct snapshot_buffer *snapshot,
                               uint32_t value) {
    unsigned char encoded[4];
    store_le32(encoded, value);
    return snapshot_append(snapshot, encoded, sizeof(encoded));
}

static int snapshot_append_u64(struct snapshot_buffer *snapshot,
                               uint64_t value) {
    unsigned char encoded[8];
    store_le64(encoded, value);
    return snapshot_append(snapshot, encoded, sizeof(encoded));
}

static void free_name_list(struct name_list *names) {
    size_t index;
    for (index = 0U; index < names->count; ++index) {
        free(names->items[index]);
    }
    free(names->items);
    memset(names, 0, sizeof(*names));
}

static int compare_names(const void *left, const void *right) {
    const char *const *left_name = left;
    const char *const *right_name = right;
    return strcmp(*left_name, *right_name);
}

static int read_sorted_names(int directory_descriptor,
                             struct name_list *names) {
    int duplicate = dup(directory_descriptor);
    DIR *directory;
    struct dirent *entry;
    if (duplicate < 0) {
        return -1;
    }
    directory = fdopendir(duplicate);
    if (directory == NULL) {
        (void)close(duplicate);
        return -1;
    }
    for (;;) {
        char *copy;
        char **expanded;
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                (void)closedir(directory);
                free_name_list(names);
                return -1;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strchr(entry->d_name, '/') != NULL) {
            (void)closedir(directory);
            free_name_list(names);
            return -1;
        }
        copy = strdup(entry->d_name);
        if (copy == NULL) {
            (void)closedir(directory);
            free_name_list(names);
            return -1;
        }
        if (names->count == names->capacity) {
            size_t next = names->capacity == 0U ? 16U :
                          names->capacity * 2U;
            if (next < names->capacity ||
                next > SIZE_MAX / sizeof(*names->items)) {
                free(copy);
                (void)closedir(directory);
                free_name_list(names);
                return -1;
            }
            expanded = realloc(names->items,
                               next * sizeof(*names->items));
            if (expanded == NULL) {
                free(copy);
                (void)closedir(directory);
                free_name_list(names);
                return -1;
            }
            names->items = expanded;
            names->capacity = next;
        }
        names->items[names->count++] = copy;
    }
    if (closedir(directory) != 0) {
        free_name_list(names);
        return -1;
    }
    if (names->count > 1U) {
        qsort(names->items, names->count, sizeof(*names->items), compare_names);
    }
    return 0;
}

static int snapshot_record_header(struct snapshot_buffer *snapshot,
                                  unsigned char type, mode_t mode,
                                  const char *path, uint64_t payload_bytes) {
    unsigned char fixed[4] = {type, 0U, 0U, 0U};
    size_t path_bytes = strlen(path);
    if (path_bytes > SNAPSHOT_MAX_PATH_BYTES ||
        snapshot->entries >= SNAPSHOT_MAX_ENTRIES) {
        return snapshot_force_overflow(snapshot);
    }
    if (path_bytes > UINT32_MAX || snapshot->entries == UINT32_MAX ||
        snapshot_append(snapshot, fixed, sizeof(fixed)) != 0 ||
        snapshot_append_u32(snapshot, (uint32_t)(mode & 07777U)) != 0 ||
        snapshot_append_u32(snapshot, (uint32_t)path_bytes) != 0 ||
        snapshot_append_u64(snapshot, payload_bytes) != 0 ||
        snapshot_append(snapshot, path, path_bytes) != 0) {
        return snapshot->overflow ? 1 : -1;
    }
    ++snapshot->entries;
    return 0;
}

static char *join_snapshot_path(const char *parent, const char *name) {
    size_t parent_bytes = strlen(parent);
    size_t name_bytes = strlen(name);
    size_t separator = parent_bytes == 0U ? 0U : 1U;
    char *joined;
    if (parent_bytes > SIZE_MAX - name_bytes - separator - 1U) {
        return NULL;
    }
    joined = malloc(parent_bytes + separator + name_bytes + 1U);
    if (joined == NULL) {
        return NULL;
    }
    memcpy(joined, parent, parent_bytes);
    if (separator != 0U) {
        joined[parent_bytes] = '/';
    }
    memcpy(joined + parent_bytes + separator, name, name_bytes + 1U);
    return joined;
}

static int snapshot_directory(struct snapshot_buffer *snapshot,
                              int directory_descriptor, const char *path,
                              const struct stat *directory_status,
                              unsigned int depth);

static int snapshot_regular(struct snapshot_buffer *snapshot,
                            int parent_descriptor, const char *name,
                            const char *path, const struct stat *before) {
    unsigned char block[CAPTURE_BLOCK_BYTES];
    struct stat after;
    int descriptor;
    uint64_t remaining;
    int header;
    if (before->st_size < 0 ||
        (uint64_t)before->st_size > SNAPSHOT_MAX_REGULAR_BYTES ||
        snapshot->total_payload_bytes >
            SNAPSHOT_MAX_TOTAL_PAYLOAD_BYTES - (uint64_t)before->st_size) {
        return snapshot_force_overflow(snapshot);
    }
    snapshot->total_payload_bytes += (uint64_t)before->st_size;
    if (snapshot->total_payload_bytes >
        SNAPSHOT_MAX_TOTAL_PAYLOAD_BYTES) {
        return snapshot_force_overflow(snapshot);
    }
    header = snapshot_record_header(snapshot, SNAPSHOT_REGULAR,
                                    before->st_mode, path,
                                    (uint64_t)before->st_size);
    if (header != 0) {
        return header;
    }
    descriptor = openat(parent_descriptor, name,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &after) != 0 ||
        !S_ISREG(after.st_mode) || after.st_dev != before->st_dev ||
        after.st_ino != before->st_ino || after.st_size != before->st_size ||
        after.st_mode != before->st_mode) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return -1;
    }
    remaining = (uint64_t)before->st_size;
    while (remaining > 0U) {
        size_t requested = remaining < sizeof(block) ?
                           (size_t)remaining : sizeof(block);
        ssize_t amount;
        do {
            amount = read(descriptor, block, requested);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0) {
            (void)close(descriptor);
            return -1;
        }
        remaining -= (uint64_t)amount;
        if (snapshot_append(snapshot, block, (size_t)amount) != 0) {
            (void)close(descriptor);
            return 1;
        }
    }
    do {
        ssize_t extra = read(descriptor, block, 1U);
        if (extra > 0) {
            (void)close(descriptor);
            return -1;
        }
        if (extra == 0) {
            break;
        }
        if (errno != EINTR) {
            (void)close(descriptor);
            return -1;
        }
    } while (1);
    if (fstat(descriptor, &after) != 0 || after.st_dev != before->st_dev ||
        after.st_ino != before->st_ino || after.st_size != before->st_size ||
        after.st_mode != before->st_mode || close(descriptor) != 0) {
        return -1;
    }
    return 0;
}

static int snapshot_symlink(struct snapshot_buffer *snapshot,
                            int parent_descriptor, const char *name,
                            const char *path, const struct stat *before) {
    size_t target_capacity;
    char *target;
    ssize_t target_bytes;
    int header;
    if (before->st_size < 0 ||
        (uint64_t)before->st_size >
            SNAPSHOT_MAX_SYMLINK_TARGET_BYTES ||
        snapshot->total_payload_bytes >
            SNAPSHOT_MAX_TOTAL_PAYLOAD_BYTES - (uint64_t)before->st_size) {
        return snapshot_force_overflow(snapshot);
    }
    snapshot->total_payload_bytes += (uint64_t)before->st_size;
    target_capacity = (size_t)before->st_size + 1U;
    if (target_capacity < 2U) {
        target_capacity = 2U;
    }
    target = malloc(target_capacity);
    if (target == NULL) {
        return -1;
    }
    target_bytes = readlinkat(parent_descriptor, name, target,
                              target_capacity);
    if (target_bytes < 0 || (size_t)target_bytes >= target_capacity ||
        target_bytes != before->st_size) {
        free(target);
        return -1;
    }
    header = snapshot_record_header(snapshot, SNAPSHOT_SYMLINK,
                                    before->st_mode, path,
                                    (uint64_t)target_bytes);
    if (header == 0 &&
        snapshot_append(snapshot, target, (size_t)target_bytes) != 0) {
        header = 1;
    }
    free(target);
    return header;
}

static int snapshot_directory(struct snapshot_buffer *snapshot,
                              int directory_descriptor, const char *path,
                              const struct stat *directory_status,
                              unsigned int depth) {
    struct name_list names;
    size_t index;
    int header;
    memset(&names, 0, sizeof(names));
    if (depth > SNAPSHOT_MAX_DEPTH) {
        return snapshot_force_overflow(snapshot);
    }
    header = snapshot_record_header(snapshot, SNAPSHOT_DIRECTORY,
                                    directory_status->st_mode, path, 0U);
    if (header != 0) {
        return header;
    }
    if (read_sorted_names(directory_descriptor, &names) != 0) {
        return -1;
    }
    if (depth >= SNAPSHOT_MAX_DEPTH && names.count > 0U) {
        free_name_list(&names);
        return snapshot_force_overflow(snapshot);
    }
    for (index = 0U; index < names.count; ++index) {
        struct stat status;
        char *child_path;
        int result;
        if (depth == 0U && strcmp(names.items[index], "input") == 0) {
            continue;
        }
        child_path = join_snapshot_path(path, names.items[index]);
        if (child_path == NULL ||
            fstatat(directory_descriptor, names.items[index], &status,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            free(child_path);
            free_name_list(&names);
            return -1;
        }
        if (S_ISDIR(status.st_mode)) {
            int child_descriptor = openat(
                directory_descriptor, names.items[index],
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            struct stat opened;
            if (child_descriptor < 0 || fstat(child_descriptor, &opened) != 0 ||
                opened.st_dev != status.st_dev ||
                opened.st_ino != status.st_ino ||
                opened.st_mode != status.st_mode) {
                if (child_descriptor >= 0) {
                    (void)close(child_descriptor);
                }
                free(child_path);
                free_name_list(&names);
                return -1;
            }
            result = snapshot_directory(snapshot, child_descriptor,
                                        child_path, &opened, depth + 1U);
            if (close(child_descriptor) != 0 && result == 0) {
                result = -1;
            }
        } else if (S_ISREG(status.st_mode)) {
            result = snapshot_regular(snapshot, directory_descriptor,
                                      names.items[index], child_path, &status);
        } else if (S_ISLNK(status.st_mode)) {
            result = snapshot_symlink(snapshot, directory_descriptor,
                                      names.items[index], child_path, &status);
        } else {
            result = -1;
        }
        free(child_path);
        if (result != 0) {
            free_name_list(&names);
            return result;
        }
    }
    free_name_list(&names);
    return 0;
}

static int build_workspace_snapshot(uint64_t cap,
                                    struct snapshot_buffer *snapshot) {
    unsigned char header[16];
    struct stat root_status;
    int root_descriptor;
    int result;
    if (cap > MAX_WORKSPACE_SNAPSHOT_BYTES || cap == UINT64_MAX) {
        return -1;
    }
    snapshot->ceiling = (size_t)(cap + 1U);
    snapshot->bytes = malloc(snapshot->ceiling);
    if (snapshot->bytes == NULL) {
        return -1;
    }
    memset(header, 0, sizeof(header));
    memcpy(header, SNAPSHOT_MAGIC, sizeof(SNAPSHOT_MAGIC));
    store_le32(header + 8U, 1U);
    if (snapshot_append(snapshot, header, sizeof(header)) != 0) {
        return 1;
    }
    root_descriptor = open("/workspace",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_descriptor < 0 || fstat(root_descriptor, &root_status) != 0 ||
        !S_ISDIR(root_status.st_mode)) {
        if (root_descriptor >= 0) {
            (void)close(root_descriptor);
        }
        return -1;
    }
    result = snapshot_directory(snapshot, root_descriptor, "", &root_status,
                                0U);
    if (close(root_descriptor) != 0 && result == 0) {
        result = -1;
    }
    if (result == 0) {
        store_le32(snapshot->bytes + 12U, snapshot->entries);
    }
    return result;
}

static uint32_t classify_outcome(
    uint32_t flags, uint32_t process_status, int32_t child_exit_code) {
    /* Exact V2 resource and process precedence. */
    if ((flags & FLAG_WORKSPACE_SNAPSHOT_OVERFLOW) != 0U) {
        return OUTCOME_WORKSPACE_SNAPSHOT_OVERFLOW;
    }
    if ((flags & FLAG_STDOUT_OVERFLOW) != 0U) {
        return OUTCOME_STDOUT_OVERFLOW;
    }
    if ((flags & FLAG_STDERR_OVERFLOW) != 0U) {
        return OUTCOME_STDERR_OVERFLOW;
    }
    if ((flags & FLAG_CPU_LIMIT_REACHED) != 0U) {
        return OUTCOME_CPU_LIMIT;
    }
    if ((flags & FLAG_WALL_LIMIT_REACHED) != 0U) {
        return OUTCOME_WALL_TIMEOUT;
    }
    if (process_status == PROCESS_SIGNALED) {
        return OUTCOME_SIGNAL;
    }
    if (process_status == PROCESS_EXITED) {
        return child_exit_code == 0 ? OUTCOME_NORMAL : OUTCOME_NONZERO;
    }
    return OUTCOME_SUPERVISOR_ERROR;
}

static int write_result(const struct request *request, uint32_t outcome,
                        uint32_t process_status, int32_t child_exit_code,
                        uint32_t child_signal, uint32_t flags,
                        const struct capture_state *stdout_capture,
                        const struct capture_state *stderr_capture,
                        const struct supervisor_state *state,
                        uint64_t wall_usec, uint64_t snapshot_bytes,
                        uint64_t cumulative_cpu_usec,
                        const unsigned char stdout_digest[32],
                        const unsigned char stderr_digest[32],
                        const unsigned char snapshot_digest[32]) {
    unsigned char result[RESULT_BYTES];
    unsigned char digest[32];
    memset(result, 0, sizeof(result));
    memcpy(result, RESULT_MAGIC, sizeof(RESULT_MAGIC));
    store_le32(result + RESULT_OFFSET_VERSION, PROTOCOL_VERSION);
    store_le32(result + RESULT_OFFSET_OUTCOME, outcome);
    store_le32(result + RESULT_OFFSET_PROCESS_STATUS, process_status);
    store_le32(result + RESULT_OFFSET_CHILD_EXIT_CODE,
               (uint32_t)child_exit_code);
    store_le32(result + RESULT_OFFSET_CHILD_SIGNAL, child_signal);
    store_le32(result + RESULT_OFFSET_FLAGS, flags);
    store_le64(result + RESULT_OFFSET_STDOUT_OBSERVED,
               stdout_capture->observed);
    store_le64(result + RESULT_OFFSET_STDERR_OBSERVED,
               stderr_capture->observed);
    store_le64(result + RESULT_OFFSET_WAIT4_USER_CPU_USEC,
               state->user_cpu_usec);
    store_le64(result + RESULT_OFFSET_WAIT4_SYS_CPU_USEC,
               state->sys_cpu_usec);
    store_le64(result + RESULT_OFFSET_WALL_USEC, wall_usec);
    store_le32(result + RESULT_OFFSET_DESCENDANTS_REAPED,
               state->descendants_reaped);
    store_le32(result + RESULT_OFFSET_RESERVED_U32, 0U);
    store_le64(result + RESULT_OFFSET_WORKSPACE_SNAPSHOT_BYTES,
               snapshot_bytes);
    store_le64(result + RESULT_OFFSET_CUMULATIVE_CPU_USEC,
               cumulative_cpu_usec);
    sha256_bytes(request->encoded, REQUEST_BYTES,
                 result + RESULT_OFFSET_REQUEST_SHA256);
    memcpy(result + RESULT_OFFSET_NONCE,
           request->encoded + REQUEST_OFFSET_NONCE, 32U);
    memcpy(result + RESULT_OFFSET_INVOCATION_SHA256,
           request->encoded + REQUEST_OFFSET_INVOCATION_SHA256, 32U);
    memcpy(result + RESULT_OFFSET_PROGRAM_SHA256,
           request->encoded + REQUEST_OFFSET_PROGRAM_SHA256, 32U);
    memcpy(result + RESULT_OFFSET_FIXTURE_DEFINITION_SHA256,
           request->encoded + REQUEST_OFFSET_FIXTURE_DEFINITION_SHA256, 32U);
    memcpy(result + RESULT_OFFSET_WORKSPACE_BASELINE_SHA256,
           request->encoded + REQUEST_OFFSET_WORKSPACE_BASELINE_SHA256, 32U);
    memcpy(result + RESULT_OFFSET_RUNTIME_SNAPSHOT_SHA256,
           request->encoded + REQUEST_OFFSET_RUNTIME_SNAPSHOT_SHA256, 32U);
    memcpy(result + RESULT_OFFSET_ALLOWED_TOOLS_SHA256,
           request->encoded + REQUEST_OFFSET_ALLOWED_TOOLS_SHA256, 32U);
    memcpy(result + RESULT_OFFSET_POLICY_SHA256,
           request->encoded + REQUEST_OFFSET_POLICY_SHA256, 32U);
    memcpy(result + RESULT_OFFSET_STDOUT_SHA256, stdout_digest, 32U);
    memcpy(result + RESULT_OFFSET_STDERR_SHA256, stderr_digest, 32U);
    memcpy(result + RESULT_OFFSET_WORKSPACE_SNAPSHOT_SHA256,
           snapshot_digest, 32U);
    sha256_bytes(result, RESULT_HASHED_PREFIX_BYTES, digest);
    memcpy(result + RESULT_OFFSET_RESULT_SHA256, digest, 32U);
    return write_all(STDOUT_FILENO, result, sizeof(result));
}

int main(void) {
    struct request request;
    struct supervisor_state state;
    struct capture_state stdout_capture;
    struct capture_state stderr_capture;
    struct snapshot_buffer snapshot;
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int ready_pipe[2] = {-1, -1};
    int ready_open = 0;
    int ready_seen = 0;
    int ready_invalid = 0;
    int infrastructure_error = 0;
    int terminating = 0;
    int wall_limit_reached = 0;
    int cpu_limit_reached = 0;
    uint64_t started = 0U;
    uint64_t finished = 0U;
    uint64_t deadline = 0U;
    uint64_t cleanup_deadline = 0U;
    uint64_t snapshot_bytes = 0U;
    uint64_t cumulative_cpu_usec = 0U;
    uint32_t flags = FLAG_REQUEST_VALIDATED;
    uint32_t process_status = PROCESS_NOT_REAPED;
    int32_t child_exit_code = -1;
    uint32_t child_signal = 0U;
    unsigned char stdout_digest[32];
    unsigned char stderr_digest[32];
    unsigned char snapshot_digest[32];
    uint32_t outcome;

    memset(&request, 0, sizeof(request));
    memset(&state, 0, sizeof(state));
    memset(&stdout_capture, 0, sizeof(stdout_capture));
    memset(&stderr_capture, 0, sizeof(stderr_capture));
    memset(&snapshot, 0, sizeof(snapshot));
    sha256_bytes((const unsigned char *)"", 0U, stdout_digest);
    memcpy(stderr_digest, stdout_digest, 32U);
    memcpy(snapshot_digest, stdout_digest, 32U);

    if (getpid() != 1 || parse_request(&request) != 0) {
        return 111;
    }
    (void)close(STDIN_FILENO);
    if (validate_program_descriptor(&request)) {
        flags |= FLAG_PROGRAM_DESCRIPTOR_VALIDATED;
    } else {
        infrastructure_error = 1;
    }
    if (validate_fixture_identity_descriptor(&request)) {
        flags |= FLAG_FIXTURE_DESCRIPTOR_VALIDATED;
    } else {
        infrastructure_error = 1;
    }
    (void)close(FIXTURE_IDENTITY_FD);
    if (fcntl(WORKSPACE_SNAPSHOT_FD, F_GETFL, 0) < 0) {
        infrastructure_error = 1;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1L, 0L, 0L, 0L) != 0 ||
        install_supervisor_signal_handlers() != 0) {
        infrastructure_error = 1;
    }

    if (!infrastructure_error &&
        (pipe2(stdout_pipe, O_CLOEXEC) != 0 ||
         pipe2(stderr_pipe, O_CLOEXEC) != 0 ||
         pipe2(ready_pipe, O_CLOEXEC) != 0 ||
         set_nonblocking(stdout_pipe[0]) != 0 ||
         set_nonblocking(stderr_pipe[0]) != 0 ||
         set_nonblocking(ready_pipe[0]) != 0)) {
        infrastructure_error = 1;
    }

    started = monotonic_microseconds();
    if (started == 0U) {
        infrastructure_error = 1;
    }
    deadline = saturating_add(started, request.wall_timeout_usec);

    if (!infrastructure_error) {
        state.primary_pid = fork();
        if (state.primary_pid < 0) {
            infrastructure_error = 1;
        } else if (state.primary_pid == 0) {
            child_main(stdout_pipe[1], stderr_pipe[1], ready_pipe[1],
                       stdout_pipe[0], stderr_pipe[0], ready_pipe[0]);
        }
    }

    if (state.primary_pid > 0) {
        (void)close(PROGRAM_FD);
        (void)close(stdout_pipe[1]); stdout_pipe[1] = -1;
        (void)close(stderr_pipe[1]); stderr_pipe[1] = -1;
        (void)close(ready_pipe[1]); ready_pipe[1] = -1;
        stdout_capture.descriptor = stdout_pipe[0];
        stdout_capture.open = 1;
        stdout_capture.cap = request.stdout_cap_bytes;
        stderr_capture.descriptor = stderr_pipe[0];
        stderr_capture.open = 1;
        stderr_capture.cap = request.stderr_cap_bytes;
        ready_open = 1;
        sha256_init(&stdout_capture.digest);
        sha256_init(&stderr_capture.digest);

        for (;;) {
            struct pollfd poll_descriptors[3];
            nfds_t poll_count = 0U;
            uint64_t now;
            uint64_t live_cpu = 0U;
            uint64_t total_cpu;
            int poll_result;

            if (reap_available(&state) != 0) {
                infrastructure_error = 1;
            }
            if (live_namespace_cpu_usec(&live_cpu) != 0) {
                infrastructure_error = 1;
                live_cpu = 0U;
            }
            total_cpu = saturating_add(
                saturating_add(state.user_cpu_usec, state.sys_cpu_usec),
                live_cpu);
            if (total_cpu > cumulative_cpu_usec) {
                cumulative_cpu_usec = total_cpu;
            }
            if (cumulative_cpu_usec >= request.cpu_time_limit_usec) {
                cpu_limit_reached = 1;
            }
            now = monotonic_microseconds();
            if (now == 0U) {
                infrastructure_error = 1;
                now = deadline;
            }
            if (now >= deadline) {
                wall_limit_reached = 1;
            }
            if ((state.primary_reaped || stdout_capture.overflow ||
                 stderr_capture.overflow || wall_limit_reached ||
                 cpu_limit_reached || termination_signal_received ||
                 infrastructure_error) && !terminating) {
                terminating = 1;
                kill_namespace_processes();
                cleanup_deadline = saturating_add(now,
                                                  CLEANUP_TIMEOUT_USEC);
            }
            if (terminating && !state.all_reaped) {
                kill_namespace_processes();
                if (now >= cleanup_deadline) {
                    infrastructure_error = 1;
                    break;
                }
            }

            if (stdout_capture.open) {
                poll_descriptors[poll_count].fd = stdout_capture.descriptor;
                poll_descriptors[poll_count].events = POLLIN | POLLHUP | POLLERR;
                poll_descriptors[poll_count].revents = 0;
                ++poll_count;
            }
            if (stderr_capture.open) {
                poll_descriptors[poll_count].fd = stderr_capture.descriptor;
                poll_descriptors[poll_count].events = POLLIN | POLLHUP | POLLERR;
                poll_descriptors[poll_count].revents = 0;
                ++poll_count;
            }
            if (ready_open) {
                poll_descriptors[poll_count].fd = ready_pipe[0];
                poll_descriptors[poll_count].events = POLLIN | POLLHUP | POLLERR;
                poll_descriptors[poll_count].revents = 0;
                ++poll_count;
            }
            poll_result = poll(poll_descriptors, poll_count, 1);
            if (poll_result < 0 && errno != EINTR) {
                infrastructure_error = 1;
            }
            if (drain_capture(&stdout_capture) < 0 ||
                drain_capture(&stderr_capture) < 0 ||
                drain_ready(&ready_pipe[0], &ready_open, &ready_seen,
                            &ready_invalid) != 0) {
                infrastructure_error = 1;
            }
            if (state.all_reaped && !stdout_capture.open &&
                !stderr_capture.open && !ready_open) {
                break;
            }
        }
    }

    if (state.primary_pid > 0 && !state.all_reaped) {
        uint64_t final_deadline = saturating_add(monotonic_microseconds(),
                                                 CLEANUP_TIMEOUT_USEC);
        kill_namespace_processes();
        while (!state.all_reaped) {
            struct timespec interval = {0, 1000000L};
            if (reap_available(&state) != 0 ||
                monotonic_microseconds() >= final_deadline) {
                infrastructure_error = 1;
                break;
            }
            if (!state.all_reaped) {
                kill_namespace_processes();
                (void)nanosleep(&interval, NULL);
            }
        }
    }

    if (stdout_capture.open) {
        (void)drain_capture(&stdout_capture);
        if (stdout_capture.open) {
            (void)close(stdout_capture.descriptor);
            stdout_capture.open = 0;
        }
    }
    if (stderr_capture.open) {
        (void)drain_capture(&stderr_capture);
        if (stderr_capture.open) {
            (void)close(stderr_capture.descriptor);
            stderr_capture.open = 0;
        }
    }
    if (ready_open) {
        (void)drain_ready(&ready_pipe[0], &ready_open, &ready_seen,
                          &ready_invalid);
        if (ready_open) {
            (void)close(ready_pipe[0]);
            ready_open = 0;
        }
    }
    if (stdout_pipe[1] >= 0) (void)close(stdout_pipe[1]);
    if (stderr_pipe[1] >= 0) (void)close(stderr_pipe[1]);
    if (ready_pipe[1] >= 0) (void)close(ready_pipe[1]);

    finished = monotonic_microseconds();
    if (finished == 0U || finished < started) {
        infrastructure_error = 1;
        finished = started;
    }
    if (finished >= deadline) {
        wall_limit_reached = 1;
    }
    {
        uint64_t final_wait4_cpu = saturating_add(
            state.user_cpu_usec, state.sys_cpu_usec);
        if (final_wait4_cpu > cumulative_cpu_usec) {
            cumulative_cpu_usec = final_wait4_cpu;
        }
    }
    if (cumulative_cpu_usec >= request.cpu_time_limit_usec) {
        cpu_limit_reached = 1;
    }

    if (ready_seen && !ready_invalid) {
        /* Exec may reset dumpability; this records only the pre-exec state. */
        flags |= FLAG_CHILD_NO_NEW_PRIVS |
                 FLAG_CHILD_PREEXEC_DUMPABLE_DISABLED |
                 FLAG_CHILD_SECCOMP_INSTALLED;
    } else if (state.primary_pid > 0) {
        infrastructure_error = 1;
    }
    if (stdout_capture.overflow) flags |= FLAG_STDOUT_OVERFLOW;
    if (stderr_capture.overflow) flags |= FLAG_STDERR_OVERFLOW;
    if (wall_limit_reached) flags |= FLAG_WALL_LIMIT_REACHED;
    if (cpu_limit_reached) flags |= FLAG_CPU_LIMIT_REACHED;
    if (state.primary_reaped) flags |= FLAG_PRIMARY_REAPED;
    if (state.all_reaped && state.primary_reaped) {
        flags |= FLAG_ALL_DESCENDANTS_REAPED;
    }
    if ((flags & FLAG_ALL_DESCENDANTS_REAPED) != 0U &&
        sole_namespace_pid1()) {
        flags |= FLAG_SOLE_PID1;
    } else if (state.primary_pid > 0) {
        infrastructure_error = 1;
    }

    if (state.primary_reaped) {
        if (WIFEXITED(state.primary_wait_status)) {
            process_status = PROCESS_EXITED;
            child_exit_code = WEXITSTATUS(state.primary_wait_status);
        } else if (WIFSIGNALED(state.primary_wait_status)) {
            process_status = PROCESS_SIGNALED;
            child_signal = (uint32_t)WTERMSIG(state.primary_wait_status);
        } else {
            infrastructure_error = 1;
        }
    }

    if ((flags & FLAG_SOLE_PID1) != 0U) {
        int snapshot_result = build_workspace_snapshot(
            request.workspace_snapshot_cap_bytes, &snapshot);
        if (snapshot_result >= 0 && snapshot.bytes != NULL &&
            snapshot.used > 0U &&
            write_all(WORKSPACE_SNAPSHOT_FD, snapshot.bytes,
                      snapshot.used) == 0) {
            snapshot_bytes = snapshot.used;
            sha256_bytes(snapshot.bytes, snapshot.used, snapshot_digest);
            if (snapshot_result == 1 || snapshot.overflow ||
                snapshot.used ==
                    (size_t)(request.workspace_snapshot_cap_bytes + 1U)) {
                flags |= FLAG_WORKSPACE_SNAPSHOT_OVERFLOW;
            } else {
                flags |= FLAG_WORKSPACE_SNAPSHOT_WRITTEN;
            }
        } else {
            infrastructure_error = 1;
            snapshot_bytes = 0U;
            sha256_bytes((const unsigned char *)"", 0U, snapshot_digest);
        }
    }
    (void)close(WORKSPACE_SNAPSHOT_FD);
    free(snapshot.bytes);

    if (state.primary_pid > 0) {
        sha256_final(&stdout_capture.digest, stdout_digest);
        sha256_final(&stderr_capture.digest, stderr_digest);
    }
    if (termination_signal_received) {
        infrastructure_error = 1;
    }
    outcome = infrastructure_error ? OUTCOME_SUPERVISOR_ERROR :
              classify_outcome(
                  flags, process_status, child_exit_code);
    if (write_result(&request, outcome, process_status, child_exit_code,
                     child_signal,
                     flags, &stdout_capture, &stderr_capture, &state,
                     finished - started, snapshot_bytes,
                     cumulative_cpu_usec, stdout_digest,
                     stderr_digest, snapshot_digest) != 0) {
        return 115;
    }
    return 0;
}

#define _GNU_SOURCE

/*
 * Candidate-input-free lifecycle canary for the CBDS development supervisor.
 *
 * This program is intentionally not a general command launcher.  It accepts
 * one fixed-size request selecting one of nine built-in adversarial probes,
 * forks no caller-supplied executable, and emits one fixed-size result frame.
 * Its purpose is to exercise PID-namespace lifecycle mechanics before any
 * synthesized Bash program is authorized.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
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
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "the lifecycle canary seccomp policy is currently pinned to x86-64"
#endif

#define REQUEST_BYTES 64U
#define RESULT_BYTES 256U
#define REQUEST_VERSION 1U
#define RESULT_VERSION 1U
#define MAX_CAPTURE_BYTES (1024U * 1024U)
#define CLEANUP_TIMEOUT_MILLISECONDS 1000U
#define READ_BLOCK_BYTES 4096U

static const unsigned char REQUEST_MAGIC[8] = {
    'C', 'B', 'D', 'S', 'C', 'R', 'Q', '1'
};
static const unsigned char RESULT_MAGIC[8] = {
    'C', 'B', 'D', 'S', 'S', 'R', 'S', '1'
};

enum scenario_id {
    SCENARIO_NORMAL = 1,
    SCENARIO_DOUBLE_FORK_SETSID = 2,
    SCENARIO_ZOMBIE = 3,
    SCENARIO_WALL_TIMEOUT = 4,
    SCENARIO_STDOUT_FLOOD = 5,
    SCENARIO_STDERR_FLOOD = 6,
    SCENARIO_CPU_FANOUT = 7,
    SCENARIO_FORBIDDEN_SYSCALL = 8,
    SCENARIO_RESULT_FRAME_SPOOF = 9
};

enum outcome_id {
    OUTCOME_NORMAL_EXIT = 1,
    OUTCOME_CHILD_NONZERO = 2,
    OUTCOME_CHILD_SIGNAL = 3,
    OUTCOME_WALL_TIMEOUT = 4,
    OUTCOME_STDOUT_OVERFLOW = 5,
    OUTCOME_STDERR_OVERFLOW = 6,
    OUTCOME_SUPERVISOR_ERROR = 7
};

enum result_flags {
    FLAG_REQUEST_VALIDATED = 1U << 0,
    FLAG_PID1_VERIFIED = 1U << 1,
    FLAG_NO_NEW_PRIVS = 1U << 2,
    FLAG_DUMPABLE_DISABLED = 1U << 3,
    FLAG_SECCOMP_INSTALLED = 1U << 4,
    FLAG_STDOUT_OVERFLOW = 1U << 5,
    FLAG_STDERR_OVERFLOW = 1U << 6,
    FLAG_TIMED_OUT = 1U << 7,
    FLAG_PRIMARY_REAPED = 1U << 8,
    FLAG_ALL_DESCENDANTS_REAPED = 1U << 9,
    FLAG_SOLE_PID1 = 1U << 10,
    FLAG_TERMINATION_SIGNAL_RECEIVED = 1U << 11
};

struct request {
    uint32_t scenario;
    uint32_t timeout_ms;
    uint32_t stdout_cap;
    uint32_t stderr_cap;
    unsigned char nonce[32];
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
    uint32_t cap;
    int descriptor;
    int open;
    int overflow;
};

struct supervisor_state {
    pid_t primary_pid;
    int primary_reaped;
    int primary_status;
    int all_reaped;
    uint32_t descendants_reaped;
    uint64_t user_cpu_usec;
    uint64_t sys_cpu_usec;
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

static void store_be32(unsigned char *destination, uint32_t value) {
    destination[0] = (unsigned char)(value >> 24);
    destination[1] = (unsigned char)(value >> 16);
    destination[2] = (unsigned char)(value >> 8);
    destination[3] = (unsigned char)value;
}

static uint32_t load_le32(const unsigned char *source) {
    return (uint32_t)source[0] |
           ((uint32_t)source[1] << 8) |
           ((uint32_t)source[2] << 16) |
           ((uint32_t)source[3] << 24);
}

static void store_le32(unsigned char *destination, uint32_t value) {
    destination[0] = (unsigned char)value;
    destination[1] = (unsigned char)(value >> 8);
    destination[2] = (unsigned char)(value >> 16);
    destination[3] = (unsigned char)(value >> 24);
}

static void store_le64(unsigned char *destination, uint64_t value) {
    unsigned int index;
    for (index = 0; index < 8U; ++index) {
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

    for (index = 0; index < 16U; ++index) {
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
    for (index = 0; index < 64U; ++index) {
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
    for (index = 0; index < 8U; ++index) {
        context->block[63U - index] =
            (unsigned char)(original_bits >> (index * 8U));
    }
    sha256_transform(context, context->block);
    for (index = 0; index < 8U; ++index) {
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

static int read_exact_request(unsigned char destination[REQUEST_BYTES]) {
    size_t used = 0U;
    while (used < REQUEST_BYTES) {
        ssize_t amount = read(STDIN_FILENO, destination + used,
                              REQUEST_BYTES - used);
        if (amount > 0) {
            used += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        return -1;
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
    uint32_t version;
    unsigned int index;
    int nonce_nonzero = 0;
    if (read_exact_request(request->encoded) != 0) {
        return -1;
    }
    if (memcmp(request->encoded, REQUEST_MAGIC, sizeof(REQUEST_MAGIC)) != 0) {
        return -1;
    }
    version = load_le32(request->encoded + 8U);
    request->scenario = load_le32(request->encoded + 12U);
    request->timeout_ms = load_le32(request->encoded + 16U);
    request->stdout_cap = load_le32(request->encoded + 20U);
    request->stderr_cap = load_le32(request->encoded + 24U);
    if (version != REQUEST_VERSION ||
        request->scenario < SCENARIO_NORMAL ||
        request->scenario > SCENARIO_RESULT_FRAME_SPOOF ||
        request->timeout_ms < 10U || request->timeout_ms > 5000U ||
        request->stdout_cap < 1U || request->stdout_cap > MAX_CAPTURE_BYTES ||
        request->stderr_cap < 1U || request->stderr_cap > MAX_CAPTURE_BYTES ||
        load_le32(request->encoded + 28U) != 0U) {
        return -1;
    }
    memcpy(request->nonce, request->encoded + 32U, sizeof(request->nonce));
    for (index = 0; index < sizeof(request->nonce); ++index) {
        nonce_nonzero |= request->nonce[index] != 0U;
    }
    return nonce_nonzero ? 0 : -1;
}

static uint64_t monotonic_microseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        return 0U;
    }
    return (uint64_t)value.tv_sec * 1000000U +
           (uint64_t)value.tv_nsec / 1000U;
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
    if (sigaction(SIGPIPE, &action, NULL) != 0) {
        return -1;
    }
    return 0;
}

#define ALLOW_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int install_child_seccomp(void) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
        ALLOW_SYSCALL(SYS_read),
        ALLOW_SYSCALL(SYS_write),
        ALLOW_SYSCALL(SYS_close),
        ALLOW_SYSCALL(SYS_exit),
        ALLOW_SYSCALL(SYS_exit_group),
        ALLOW_SYSCALL(SYS_rt_sigreturn),
        ALLOW_SYSCALL(SYS_rt_sigprocmask),
        ALLOW_SYSCALL(SYS_clone),
        ALLOW_SYSCALL(SYS_pipe2),
        ALLOW_SYSCALL(SYS_setsid),
        ALLOW_SYSCALL(SYS_nanosleep),
        ALLOW_SYSCALL(SYS_clock_nanosleep),
        ALLOW_SYSCALL(SYS_pause),
        ALLOW_SYSCALL(SYS_restart_syscall),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
    };
    struct sock_fprog program;
    program.len = (unsigned short)(sizeof(instructions) /
                                   sizeof(instructions[0]));
    program.filter = instructions;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        return -1;
    }
    return 0;
}

static int write_all_child(int descriptor, const unsigned char *data,
                           size_t size) {
    while (size > 0U) {
        ssize_t amount = write(descriptor, data, size);
        if (amount > 0) {
            data += (size_t)amount;
            size -= (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static pid_t raw_fork_like(void) {
    long result = syscall(SYS_clone, (unsigned long)SIGCHLD,
                          (void *)0, (void *)0, (void *)0, 0UL);
    if (result < 0) {
        return (pid_t)-1;
    }
    return (pid_t)result;
}

static void raw_sleep_milliseconds(unsigned int milliseconds) {
    struct timespec interval;
    interval.tv_sec = (time_t)(milliseconds / 1000U);
    interval.tv_nsec = (long)(milliseconds % 1000U) * 1000000L;
    while (syscall(SYS_nanosleep, &interval, &interval) != 0 &&
           errno == EINTR) {
    }
}

static void pause_forever(void) {
    for (;;) {
        (void)syscall(SYS_pause);
    }
}

static void burn_forever(void) {
    volatile uint64_t value = 0x9e3779b97f4a7c15ULL;
    for (;;) {
        value ^= value << 7;
        value ^= value >> 9;
        value *= 0xbf58476d1ce4e5b9ULL;
    }
}

static int run_fixed_scenario(uint32_t scenario) {
    static const unsigned char normal_stdout[] = "child-normal-stdout\n";
    static const unsigned char normal_stderr[] = "child-normal-stderr\n";
    static const unsigned char escape_ready[] = "escape-ready\n";
    static const unsigned char zombie_ready[] = "zombie-ready\n";
    static const unsigned char spoof[] = "CBDSSRS1-child-spoof\n";
    static const unsigned char stdout_flood[4096] = {[0 ... 4095] = 'O'};
    static const unsigned char stderr_flood[4096] = {[0 ... 4095] = 'E'};

    switch (scenario) {
    case SCENARIO_NORMAL:
        if (write_all_child(STDOUT_FILENO, normal_stdout,
                            sizeof(normal_stdout) - 1U) != 0 ||
            write_all_child(STDERR_FILENO, normal_stderr,
                            sizeof(normal_stderr) - 1U) != 0) {
            return 20;
        }
        return 0;
    case SCENARIO_DOUBLE_FORK_SETSID: {
        int synchronization[2];
        unsigned char ready_byte = 0U;
        pid_t intermediate;
        if (syscall(SYS_pipe2, synchronization, O_CLOEXEC) != 0) {
            return 21;
        }
        intermediate = raw_fork_like();
        if (intermediate < 0) {
            (void)close(synchronization[0]);
            (void)close(synchronization[1]);
            return 22;
        }
        if (intermediate == 0) {
            static const unsigned char daemon_ready = 'D';
            pid_t daemon;
            (void)close(synchronization[0]);
            if (syscall(SYS_setsid) < 0) {
                _exit(23);
            }
            daemon = raw_fork_like();
            if (daemon < 0) {
                _exit(24);
            }
            if (daemon == 0) {
                (void)close(synchronization[1]);
                pause_forever();
            }
            if (write_all_child(synchronization[1], &daemon_ready, 1U) != 0) {
                _exit(25);
            }
            (void)close(synchronization[1]);
            _exit(0);
        }
        (void)close(synchronization[1]);
        while (read(synchronization[0], &ready_byte, 1U) < 0 && errno == EINTR) {
        }
        (void)close(synchronization[0]);
        if (ready_byte != 'D') {
            return 26;
        }
        if (write_all_child(STDOUT_FILENO, escape_ready,
                            sizeof(escape_ready) - 1U) != 0) {
            return 27;
        }
        return 0;
    }
    case SCENARIO_ZOMBIE: {
        pid_t descendant = raw_fork_like();
        if (descendant < 0) {
            return 28;
        }
        if (descendant == 0) {
            _exit(0);
        }
        raw_sleep_milliseconds(30U);
        if (write_all_child(STDOUT_FILENO, zombie_ready,
                            sizeof(zombie_ready) - 1U) != 0) {
            return 29;
        }
        return 0;
    }
    case SCENARIO_WALL_TIMEOUT:
        pause_forever();
        return 30;
    case SCENARIO_STDOUT_FLOOD:
        for (;;) {
            if (write_all_child(STDOUT_FILENO, stdout_flood,
                                sizeof(stdout_flood)) != 0) {
                return 31;
            }
        }
    case SCENARIO_STDERR_FLOOD:
        for (;;) {
            if (write_all_child(STDERR_FILENO, stderr_flood,
                                sizeof(stderr_flood)) != 0) {
                return 32;
            }
        }
    case SCENARIO_CPU_FANOUT: {
        unsigned int index;
        for (index = 0; index < 3U; ++index) {
            pid_t descendant = raw_fork_like();
            if (descendant < 0) {
                return 33;
            }
            if (descendant == 0) {
                burn_forever();
            }
        }
        burn_forever();
        return 34;
    }
    case SCENARIO_FORBIDDEN_SYSCALL:
        (void)syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
        return 35;
    case SCENARIO_RESULT_FRAME_SPOOF:
        return write_all_child(STDOUT_FILENO, spoof,
                               sizeof(spoof) - 1U) == 0 ? 0 : 36;
    default:
        return 37;
    }
}

static void close_child_descriptors(void) {
    unsigned int descriptor;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 4U, ~0U, 0U) == 0) {
        return;
    }
#endif
    for (descriptor = 4U; descriptor < 4096U; ++descriptor) {
        (void)close((int)descriptor);
    }
}

static void child_main(uint32_t scenario, int stdout_write, int stderr_write,
                       int ready_write, int stdout_read, int stderr_read,
                       int ready_read) {
    static const unsigned char ready = 'R';
    int code;
    (void)close(stdout_read);
    (void)close(stderr_read);
    (void)close(ready_read);
    if (dup2(stdout_write, STDOUT_FILENO) < 0 ||
        dup2(stderr_write, STDERR_FILENO) < 0 ||
        dup2(ready_write, 3) < 0) {
        _exit(100);
    }
    close_child_descriptors();
    (void)close(STDIN_FILENO);
    if (prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0 ||
        install_child_seccomp() != 0) {
        _exit(101);
    }
    if (write_all_child(3, &ready, 1U) != 0) {
        _exit(102);
    }
    (void)close(3);
    code = run_fixed_scenario(scenario);
    _exit(code);
}

static int set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }
    return 0;
}

static void add_rusage(struct supervisor_state *state,
                       const struct rusage *usage) {
    state->user_cpu_usec += (uint64_t)usage->ru_utime.tv_sec * 1000000U +
                            (uint64_t)usage->ru_utime.tv_usec;
    state->sys_cpu_usec += (uint64_t)usage->ru_stime.tv_sec * 1000000U +
                           (uint64_t)usage->ru_stime.tv_usec;
}

static int reap_available(struct supervisor_state *state) {
    for (;;) {
        struct rusage usage;
        int status = 0;
        pid_t reaped;
        memset(&usage, 0, sizeof(usage));
        reaped = wait4(-1, &status, WNOHANG, &usage);
        if (reaped > 0) {
            ++state->descendants_reaped;
            add_rusage(state, &usage);
            if (reaped == state->primary_pid) {
                state->primary_reaped = 1;
                state->primary_status = status;
            }
            continue;
        }
        if (reaped == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == ECHILD) {
            state->all_reaped = 1;
            return 0;
        }
        return -1;
    }
}

static void kill_namespace_processes(void) {
    if (kill(-1, SIGKILL) != 0 && errno != ESRCH) {
        /* Cleanup verification below remains authoritative. */
    }
}

static int drain_capture(struct capture_state *capture) {
    unsigned char block[READ_BLOCK_BYTES];
    while (capture->open) {
        uint64_t ceiling = (uint64_t)capture->cap + 1U;
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
            if (capture->observed > capture->cap) {
                capture->overflow = 1;
                (void)close(capture->descriptor);
                capture->descriptor = -1;
                capture->open = 0;
                return 1;
            }
            continue;
        }
        if (amount == 0) {
            (void)close(capture->descriptor);
            capture->descriptor = -1;
            capture->open = 0;
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return 0;
}

static int drain_ready(int *descriptor, int *open, int *ready_seen,
                       int *ready_invalid) {
    unsigned char block[2];
    while (*open) {
        ssize_t amount = read(*descriptor, block, sizeof(block));
        if (amount > 0) {
            if (amount != 1 || block[0] != 'R' || *ready_seen) {
                *ready_invalid = 1;
            } else {
                *ready_seen = 1;
            }
            continue;
        }
        if (amount == 0) {
            (void)close(*descriptor);
            *descriptor = -1;
            *open = 0;
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
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
        if (text[0] == '\0') {
            continue;
        }
        while (text[index] >= '0' && text[index] <= '9') {
            ++index;
        }
        if (text[index] != '\0' || index == 0U) {
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

static int write_result(const struct request *request, uint32_t outcome,
                        int32_t child_exit_code, uint32_t child_signal,
                        uint32_t flags,
                        const struct capture_state *stdout_capture,
                        const struct capture_state *stderr_capture,
                        const struct supervisor_state *state,
                        uint64_t wall_usec,
                        const unsigned char stdout_digest[32],
                        const unsigned char stderr_digest[32]) {
    unsigned char result[RESULT_BYTES];
    unsigned char digest[32];
    size_t written = 0U;
    memset(result, 0, sizeof(result));
    memcpy(result, RESULT_MAGIC, sizeof(RESULT_MAGIC));
    store_le32(result + 8U, RESULT_VERSION);
    store_le32(result + 12U, request->scenario);
    store_le32(result + 16U, outcome);
    store_le32(result + 20U, (uint32_t)child_exit_code);
    store_le32(result + 24U, child_signal);
    store_le32(result + 28U, flags);
    store_le64(result + 32U, stdout_capture->observed);
    store_le64(result + 40U, stderr_capture->observed);
    store_le32(result + 48U, state->descendants_reaped);
    store_le64(result + 56U, state->user_cpu_usec);
    store_le64(result + 64U, state->sys_cpu_usec);
    store_le64(result + 72U, wall_usec);
    sha256_bytes(request->encoded, REQUEST_BYTES, result + 96U);
    memcpy(result + 128U, stdout_digest, 32U);
    memcpy(result + 160U, stderr_digest, 32U);
    memcpy(result + 192U, request->nonce, sizeof(request->nonce));
    sha256_bytes(result, 224U, digest);
    memcpy(result + 224U, digest, sizeof(digest));
    while (written < sizeof(result)) {
        ssize_t amount = write(STDOUT_FILENO, result + written,
                               sizeof(result) - written);
        if (amount > 0) {
            written += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

int main(void) {
    struct request request;
    struct supervisor_state state;
    struct capture_state stdout_capture;
    struct capture_state stderr_capture;
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int ready_pipe[2] = {-1, -1};
    int ready_open = 0;
    int ready_seen = 0;
    int ready_invalid = 0;
    int terminating = 0;
    int timed_out = 0;
    int infrastructure_error = 0;
    uint64_t started;
    uint64_t deadline;
    uint64_t cleanup_deadline = 0U;
    uint64_t finished;
    uint32_t flags = FLAG_REQUEST_VALIDATED | FLAG_PID1_VERIFIED;
    uint32_t outcome;
    int32_t child_exit_code = -1;
    uint32_t child_signal = 0U;
    unsigned char stdout_digest[32];
    unsigned char stderr_digest[32];

    memset(&request, 0, sizeof(request));
    memset(&state, 0, sizeof(state));
    memset(&stdout_capture, 0, sizeof(stdout_capture));
    memset(&stderr_capture, 0, sizeof(stderr_capture));
    if (getpid() != 1 || parse_request(&request) != 0) {
        return 111;
    }
    (void)close(STDIN_FILENO);
    if (prctl(PR_SET_CHILD_SUBREAPER, 1L, 0L, 0L, 0L) != 0 ||
        install_supervisor_signal_handlers() != 0 ||
        pipe2(stdout_pipe, O_CLOEXEC) != 0 ||
        pipe2(stderr_pipe, O_CLOEXEC) != 0 ||
        pipe2(ready_pipe, O_CLOEXEC) != 0 ||
        set_nonblocking(stdout_pipe[0]) != 0 ||
        set_nonblocking(stderr_pipe[0]) != 0 ||
        set_nonblocking(ready_pipe[0]) != 0) {
        return 112;
    }

    started = monotonic_microseconds();
    if (started == 0U) {
        return 113;
    }
    deadline = started + (uint64_t)request.timeout_ms * 1000U;
    state.primary_pid = fork();
    if (state.primary_pid < 0) {
        return 114;
    }
    if (state.primary_pid == 0) {
        child_main(request.scenario, stdout_pipe[1], stderr_pipe[1],
                   ready_pipe[1], stdout_pipe[0], stderr_pipe[0],
                   ready_pipe[0]);
    }

    (void)close(stdout_pipe[1]); stdout_pipe[1] = -1;
    (void)close(stderr_pipe[1]); stderr_pipe[1] = -1;
    (void)close(ready_pipe[1]); ready_pipe[1] = -1;
    stdout_capture.descriptor = stdout_pipe[0];
    stdout_capture.open = 1;
    stdout_capture.cap = request.stdout_cap;
    stderr_capture.descriptor = stderr_pipe[0];
    stderr_capture.open = 1;
    stderr_capture.cap = request.stderr_cap;
    ready_open = 1;
    sha256_init(&stdout_capture.digest);
    sha256_init(&stderr_capture.digest);

    for (;;) {
        struct pollfd poll_fds[3];
        nfds_t poll_count = 0U;
        uint64_t now;
        int timeout_ms = 10;
        int poll_result;

        if (reap_available(&state) != 0) {
            infrastructure_error = 1;
        }
        if (state.primary_reaped && !terminating) {
            terminating = 1;
            kill_namespace_processes();
            cleanup_deadline = monotonic_microseconds() +
                               CLEANUP_TIMEOUT_MILLISECONDS * 1000U;
        }
        if ((stdout_capture.overflow || stderr_capture.overflow ||
             termination_signal_received || infrastructure_error) &&
            !terminating) {
            terminating = 1;
            kill_namespace_processes();
            cleanup_deadline = monotonic_microseconds() +
                               CLEANUP_TIMEOUT_MILLISECONDS * 1000U;
        }

        now = monotonic_microseconds();
        if (!terminating && now >= deadline) {
            timed_out = 1;
            terminating = 1;
            kill_namespace_processes();
            cleanup_deadline = now + CLEANUP_TIMEOUT_MILLISECONDS * 1000U;
        }
        if (terminating && !state.all_reaped) {
            kill_namespace_processes();
            if (cleanup_deadline != 0U && now >= cleanup_deadline) {
                infrastructure_error = 1;
                break;
            }
        }

        if (stdout_capture.open) {
            poll_fds[poll_count].fd = stdout_capture.descriptor;
            poll_fds[poll_count].events = POLLIN | POLLHUP | POLLERR;
            poll_fds[poll_count].revents = 0;
            ++poll_count;
        }
        if (stderr_capture.open) {
            poll_fds[poll_count].fd = stderr_capture.descriptor;
            poll_fds[poll_count].events = POLLIN | POLLHUP | POLLERR;
            poll_fds[poll_count].revents = 0;
            ++poll_count;
        }
        if (ready_open) {
            poll_fds[poll_count].fd = ready_pipe[0];
            poll_fds[poll_count].events = POLLIN | POLLHUP | POLLERR;
            poll_fds[poll_count].revents = 0;
            ++poll_count;
        }
        if (!terminating) {
            uint64_t remaining = deadline > now ? deadline - now : 0U;
            if (remaining / 1000U < (uint64_t)timeout_ms) {
                timeout_ms = (int)(remaining / 1000U);
            }
        }
        if (timeout_ms < 0) {
            timeout_ms = 0;
        }
        poll_result = poll(poll_fds, poll_count, timeout_ms);
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

    if (!state.all_reaped) {
        uint64_t final_cleanup_deadline = monotonic_microseconds() +
                                          CLEANUP_TIMEOUT_MILLISECONDS * 1000U;
        kill_namespace_processes();
        while (!state.all_reaped) {
            if (reap_available(&state) != 0) {
                infrastructure_error = 1;
                break;
            }
            if (!state.all_reaped) {
                struct timespec brief = {0, 1000000L};
                if (monotonic_microseconds() >= final_cleanup_deadline) {
                    infrastructure_error = 1;
                    break;
                }
                kill_namespace_processes();
                (void)nanosleep(&brief, NULL);
            }
        }
    }
    (void)drain_capture(&stdout_capture);
    (void)drain_capture(&stderr_capture);
    (void)drain_ready(&ready_pipe[0], &ready_open, &ready_seen,
                      &ready_invalid);
    if (stdout_capture.open) {
        (void)close(stdout_capture.descriptor);
        stdout_capture.open = 0;
    }
    if (stderr_capture.open) {
        (void)close(stderr_capture.descriptor);
        stderr_capture.open = 0;
    }
    if (ready_open) {
        (void)close(ready_pipe[0]);
        ready_open = 0;
    }

    finished = monotonic_microseconds();
    if (finished == 0U || finished < started) {
        infrastructure_error = 1;
        finished = started;
    }
    if (ready_seen && !ready_invalid) {
        flags |= FLAG_NO_NEW_PRIVS | FLAG_DUMPABLE_DISABLED |
                 FLAG_SECCOMP_INSTALLED;
    } else {
        infrastructure_error = 1;
    }
    if (stdout_capture.overflow) flags |= FLAG_STDOUT_OVERFLOW;
    if (stderr_capture.overflow) flags |= FLAG_STDERR_OVERFLOW;
    if (timed_out) flags |= FLAG_TIMED_OUT;
    if (state.primary_reaped) flags |= FLAG_PRIMARY_REAPED;
    if (state.all_reaped) flags |= FLAG_ALL_DESCENDANTS_REAPED;
    if (sole_namespace_pid1()) flags |= FLAG_SOLE_PID1;
    else infrastructure_error = 1;
    if (termination_signal_received) flags |= FLAG_TERMINATION_SIGNAL_RECEIVED;

    if (state.primary_reaped) {
        if (WIFEXITED(state.primary_status)) {
            child_exit_code = WEXITSTATUS(state.primary_status);
        } else if (WIFSIGNALED(state.primary_status)) {
            child_signal = (uint32_t)WTERMSIG(state.primary_status);
        }
    }
    if (infrastructure_error) outcome = OUTCOME_SUPERVISOR_ERROR;
    else if (stdout_capture.overflow) outcome = OUTCOME_STDOUT_OVERFLOW;
    else if (stderr_capture.overflow) outcome = OUTCOME_STDERR_OVERFLOW;
    else if (timed_out) outcome = OUTCOME_WALL_TIMEOUT;
    else if (child_signal != 0U) outcome = OUTCOME_CHILD_SIGNAL;
    else if (child_exit_code != 0) outcome = OUTCOME_CHILD_NONZERO;
    else outcome = OUTCOME_NORMAL_EXIT;

    sha256_final(&stdout_capture.digest, stdout_digest);
    sha256_final(&stderr_capture.digest, stderr_digest);
    if (write_result(&request, outcome, child_exit_code, child_signal,
                     flags, &stdout_capture, &stderr_capture, &state,
                     finished - started, stdout_digest, stderr_digest) != 0) {
        return 115;
    }
    return 0;
}

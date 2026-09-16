#pragma once
#include <sched.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>
#include <seccomp.h>
#include <stdexcept>

/**
 * C++ DEMONSTRATION SANDBOX FILTER
 *
 * NOTE ON SECURITY ARCHITECTURE:
 * This seccomp + network namespace sandbox is an educational / demonstration isolation layer.
 * In a high-assurance production system, untrusted agent tool execution should be contained
 * inside hypervisor-level microVMs (e.g., AWS Firecracker) or user-space kernel emulators
 * (e.g., Google gVisor), rather than a hand-rolled seccomp filter on the host kernel.
 */

inline void isolateNetwork() {
    // Empty network namespace: no network interface exists to route through
    if (unshare(CLONE_NEWNET) != 0) {
        throw std::runtime_error("failed to isolate network namespace (requires CAP_SYS_ADMIN or user namespaces)");
    }
}

inline void limitResources() {
    // 1. CPU time limit: 5 seconds hard/soft cap
    struct rlimit cpuLimit{5, 5};
    setrlimit(RLIMIT_CPU, &cpuLimit);

    // 2. Virtual memory (address space) limit: 256MB cap
    struct rlimit memLimit{256L * 1024 * 1024, 256L * 1024 * 1024};
    setrlimit(RLIMIT_AS, &memLimit);

    // 3. Process count limit: prevent fork bombs
    struct rlimit nprocLimit{1, 1};
    setrlimit(RLIMIT_NPROC, &nprocLimit);

    // 4. File descriptor limit: limit open sockets/files
    struct rlimit nofileLimit{32, 32};
    setrlimit(RLIMIT_NOFILE, &nofileLimit);

    // 5. File write size limit: prevent disk exhaustion (4MB max)
    struct rlimit fsizeLimit{4L * 1024 * 1024, 4L * 1024 * 1024};
    setrlimit(RLIMIT_FSIZE, &fsizeLimit);

    // 6. Wall-clock timeout watchdog (10 seconds)
    alarm(10);
}

// Called by the target binary as the first instruction of main()
inline void applySyscallFilter() {
    // Prevent gaining new privileges via execve/setuid
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        throw std::runtime_error("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL); // default-deny
    if (!ctx) throw std::runtime_error("seccomp_init failed");

    // Allow strictly necessary I/O and memory management syscalls
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);

    // Explicitly blocked by default-deny (SCMP_ACT_KILL):
    // - execve, execveat (cannot spawn child processes)
    // - socket, connect, bind, accept, sendto, recvfrom (cannot initiate network connections)
    // - open, openat (cannot open fresh file descriptors outside pre-opened fds)
    // - clone, fork, vfork (cannot create threads or processes)

    if (seccomp_load(ctx) != 0) {
        seccomp_release(ctx);
        throw std::runtime_error("failed to load seccomp filter");
    }
    seccomp_release(ctx);
}

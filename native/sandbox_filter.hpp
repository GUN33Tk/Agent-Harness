#pragma once
#include <sched.h>
#include <sys/resource.h>
#include <seccomp.h>
#include <stdexcept>

inline void isolateNetwork() {
    // Empty network namespace: no interface exists to route through,
    // regardless of what the application-level egress allowlist decided.
    if (unshare(CLONE_NEWNET) != 0) {
        throw std::runtime_error("failed to isolate network namespace");
    }
}

inline void limitResources() {
    struct rlimit cpuLimit{5, 5};                                    // 5 seconds CPU time
    struct rlimit memLimit{256L * 1024 * 1024, 256L * 1024 * 1024};  // 256MB
    setrlimit(RLIMIT_CPU, &cpuLimit);
    setrlimit(RLIMIT_AS, &memLimit);
}

// Called by the TARGET binary, on itself, as literally the first line of
// its own main() — NOT by the launcher (see sandbox_executor.cpp for why).
inline void applySyscallFilter() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);   // default-deny
    if (!ctx) throw std::runtime_error("seccomp_init failed");

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    // fstat/newfstatat: libstdc++'s std::cout checks the fd's mode on its
    // first write to decide buffering — found this the hard way by
    // actually running the binary under strace, not by inspecting the
    // code. Left in as a reminder that a syscall allowlist has to be
    // built empirically against the real target binary, not guessed.
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    // execve, socket, connect are deliberately absent: this process, and
    // anything it might try to spawn, has no way to do either afterward.

    if (seccomp_load(ctx) != 0) {
        seccomp_release(ctx);
        throw std::runtime_error("failed to load seccomp filter");
    }
    seccomp_release(ctx);
}

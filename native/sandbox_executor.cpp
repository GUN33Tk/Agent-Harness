#include <sched.h>
#include <sys/resource.h>
#include <seccomp.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>

// Step 5: this file previously isolated, printed a message, and exited —
// it never ran anything. Making it real surfaces a genuine design
// question: seccomp filters are inherited across execve() (that's what
// makes them useful — a compromised child stays restricted), but this
// launcher still needs ONE execve to hand off to the actual tool binary.
//
// The correct pattern (the one container runtimes actually use) is two
// processes, not one:
//   1. This launcher: sets up namespace + resource limits, then execve's
//      into the target tool binary WITHOUT loading a seccomp filter of
//      its own — because a filter loaded here would either have to allow
//      execve (weakening it for the child too, since the restriction is
//      inherited) or block the one execve this process actually needs.
//   2. The target tool binary calls applySyscallFilter() itself, as the
//      very first line of its own main(), before touching any untrusted
//      input. From that point on, IT has no execve/socket available —
//      including to any child it might try to spawn.
//
// This file is the launcher. The filter function is kept in a header so
// the target binary can apply it to itself.

#include "sandbox_filter.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: sandbox_launcher <path-to-tool-binary> [args...]\n";
        return 1;
    }

    try {
        isolateNetwork();     // no interface exists to route through, at all
        limitResources();     // bounded CPU/memory regardless of what runs next
    } catch (const std::exception& e) {
        std::cerr << "sandbox setup failed: " << e.what() << "\n";
        return 1;
    }

    // Handoff: the target binary is responsible for calling
    // applySyscallFilter() on itself immediately after this exec.
    execv(argv[1], &argv[1]);
    perror("execv failed");   // only reached if execv itself failed
    return 1;
}

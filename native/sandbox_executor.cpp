#include <sched.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <unistd.h>
#include <stdexcept>
#include <iostream>

#include "sandbox_filter.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: sandbox_launcher <path-to-tool-binary> [args...]\n";
        return 1;
    }

    try {
        // Enforce no new privileges before namespace or exec
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            std::cerr << "sandbox warning: PR_SET_NO_NEW_PRIVS failed\n";
        }

        isolateNetwork(); // unshare(CLONE_NEWNET)
        limitResources(); // RLIMIT_CPU, RLIMIT_AS, RLIMIT_NPROC, RLIMIT_NOFILE, alarm()
    } catch (const std::exception& e) {
        std::cerr << "sandbox setup failed: " << e.what() << "\n";
        return 1;
    }

    // Handoff to target tool binary
    execv(argv[1], &argv[1]);
    perror("execv failed");
    return 1;
}

#include "sandbox_filter.hpp"
#include <iostream>

// Step 5: a stand-in for "the real tool logic." Any actual tool binary
// you hand to the launcher should follow this exact shape: apply the
// filter to itself FIRST, before touching any untrusted input, then do
// its real work.

int main(int argc, char** argv) {
    try {
        applySyscallFilter();   // from this line on: no execve, no sockets
    } catch (const std::exception& e) {
        std::cerr << "target self-filter failed: " << e.what() << "\n";
        return 1;
    }

    std::cout << "running under seccomp: no execve, no network syscalls available\n";
    // Real tool logic goes here.
    return 0;
}

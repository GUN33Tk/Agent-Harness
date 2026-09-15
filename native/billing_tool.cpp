#include "sandbox_filter.hpp"
#include <iostream>
#include <string>

// This is real tool logic, not a stand-in — read_billing's actual
// execution now happens here, inside a process with no execve and no
// network syscalls available, invoked by sandbox_executor.cpp's launcher
// from Node via child_process.execFile.

int main(int argc, char** argv) {
    try {
        applySyscallFilter();   // no execve, no sockets from this point on
    } catch (const std::exception& e) {
        std::cerr << "{\"error\":\"sandbox self-filter failed: " << e.what() << "\"}\n";
        return 1;
    }

    std::string accountId = (argc > 1) ? argv[1] : "unknown";
    // Deliberately hardcoded — this stands in for "your real billing
    // lookup," which in production would need to happen without any
    // network syscall, i.e. via a pre-opened file descriptor or a
    // unix socket passed in before the filter loaded, not a fresh
    // outbound connection from inside this process.
    std::cout << "{\"account_id\":\"" << accountId << "\",\"balance_usd\":0}\n";
    return 0;
}

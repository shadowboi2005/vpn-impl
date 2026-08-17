#include "netcfg.h"

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <stdexcept>
#include <system_error>

namespace vpn::netcfg {
namespace {

const char* find_ip_binary() {
    static constexpr const char* kCandidates[] = {
        "/usr/sbin/ip",
        "/sbin/ip",
        "/usr/bin/ip",
        "/bin/ip",
    };
    for (const char* candidate : kCandidates) {
        if (::access(candidate, X_OK) == 0) {
            return candidate;
        }
    }
    throw std::runtime_error("could not find an executable ip(8) in /usr/sbin, /sbin, /usr/bin or /bin");
}

std::string describe(const char* prog, const std::vector<std::string>& args) {
    std::string text = prog;
    for (const std::string& arg : args) {
        text += ' ';
        text += arg;
    }
    return text;
}

}  // namespace

void run_ip(const std::vector<std::string>& args) {
    const char* const prog = find_ip_binary();

    // posix_spawn wants a mutable argv. Copy into a buffer we own rather than
    // casting away const from the caller's strings.
    std::vector<std::string> owned;
    owned.reserve(args.size() + 1);
    owned.emplace_back(prog);
    owned.insert(owned.end(), args.begin(), args.end());

    std::vector<char*> argv;
    argv.reserve(owned.size() + 1);
    for (std::string& arg : owned) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);

    // ip(8) needs nothing from the environment, so it gets nothing.
    char* envp[] = {nullptr};

    pid_t pid = 0;
    const int rc = ::posix_spawn(&pid, prog, nullptr, nullptr, argv.data(), envp);
    if (rc != 0) {
        throw std::system_error(rc, std::generic_category(), "posix_spawn " + describe(prog, args));
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            throw std::system_error(errno, std::generic_category(), "waitpid for " + std::string(prog));
        }
    }

    if (WIFSIGNALED(status)) {
        throw std::runtime_error(describe(prog, args) + ": killed by signal " +
                                 std::to_string(WTERMSIG(status)));
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        throw std::runtime_error(describe(prog, args) + ": exited " +
                                 std::to_string(WEXITSTATUS(status)));
    }
}

void configure_interface(const std::string& dev, const std::string& cidr, int mtu) {
    run_ip({"link", "set", "dev", dev, "mtu", std::to_string(mtu)});
    run_ip({"addr", "add", cidr, "dev", dev});
    run_ip({"link", "set", "dev", dev, "up"});
}

}  // namespace vpn::netcfg

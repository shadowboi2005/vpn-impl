#include "netcfg.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "fd.h"

namespace vpn::netcfg {
namespace {

const char* find_binary(const char* const* candidates, size_t count, const char* what) {
    for (size_t i = 0; i < count; ++i) {
        if (::access(candidates[i], X_OK) == 0) {
            return candidates[i];
        }
    }
    throw std::runtime_error(std::string("could not find an executable ") + what +
                             " in /usr/sbin, /sbin, /usr/bin or /bin");
}

const char* binary_for(Tool tool) {
    static constexpr const char* kIp[] = {
        "/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip",
    };
    static constexpr const char* kIptables[] = {
        "/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables", "/bin/iptables",
    };
    static constexpr const char* kIp6tables[] = {
        "/usr/sbin/ip6tables", "/sbin/ip6tables", "/usr/bin/ip6tables", "/bin/ip6tables",
    };
    switch (tool) {
        case Tool::ip:
            return find_binary(kIp, std::size(kIp), "ip(8)");
        case Tool::iptables:
            return find_binary(kIptables, std::size(kIptables), "iptables(8)");
        case Tool::ip6tables:
            return find_binary(kIp6tables, std::size(kIp6tables), "ip6tables(8)");
    }
    throw std::logic_error("unknown tool");
}

void write_sysctl(const std::string& path, const std::string& value) {
    std::ofstream out(path);
    if (!out || !(out << value << '\n') || !out.flush()) {
        throw std::runtime_error("cannot write " + value + " to " + path);
    }
}

std::string_view trim(std::string_view text) {
    const size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return {};
    }
    return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}

std::string describe(const char* prog, const std::vector<std::string>& args) {
    std::string text = prog;
    for (const std::string& arg : args) {
        text += ' ';
        text += arg;
    }
    return text;
}

// posix_spawn_file_actions_t owns heap allocations; it needs destroying on every
// path out, including the throwing ones.
class SpawnActions {
public:
    SpawnActions() {
        const int rc = ::posix_spawn_file_actions_init(&actions_);
        if (rc != 0) {
            throw std::system_error(rc, std::generic_category(), "posix_spawn_file_actions_init");
        }
    }
    ~SpawnActions() { ::posix_spawn_file_actions_destroy(&actions_); }

    SpawnActions(const SpawnActions&) = delete;
    SpawnActions& operator=(const SpawnActions&) = delete;

    void dup2(int from, int to) {
        const int rc = ::posix_spawn_file_actions_adddup2(&actions_, from, to);
        if (rc != 0) {
            throw std::system_error(rc, std::generic_category(), "posix_spawn_file_actions_adddup2");
        }
    }

    posix_spawn_file_actions_t* get() noexcept { return &actions_; }

private:
    posix_spawn_file_actions_t actions_;
};

// Spawns `prog args...` and waits for it. When `output` is non-null the child's
// stdout is captured into it.
void spawn_and_wait(const char* prog, const std::vector<std::string>& args, std::string* output) {
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

    // These tools need nothing from the environment, so they get nothing.
    char* envp[] = {nullptr};

    SpawnActions actions;
    UniqueFd read_end;
    UniqueFd write_end;

    if (output != nullptr) {
        int pipe_fds[2] = {-1, -1};
        if (::pipe2(pipe_fds, O_CLOEXEC) < 0) {
            throw std::system_error(errno, std::generic_category(), "pipe2");
        }
        read_end = UniqueFd(pipe_fds[0]);
        write_end = UniqueFd(pipe_fds[1]);
        // dup2 in the child clears O_CLOEXEC on the copy, so fd 1 survives exec.
        actions.dup2(write_end.get(), STDOUT_FILENO);
    }

    pid_t pid = 0;
    const int rc = ::posix_spawn(&pid, prog, actions.get(), nullptr, argv.data(), envp);
    if (rc != 0) {
        throw std::system_error(rc, std::generic_category(), "posix_spawn " + describe(prog, args));
    }

    if (output != nullptr) {
        // Our copy of the write end must go before the read, or the child's exit
        // never produces EOF and we block forever.
        write_end.reset();
        std::array<char, 4096> chunk{};
        while (true) {
            const ssize_t n = ::read(read_end.get(), chunk.data(), chunk.size());
            if (n > 0) {
                output->append(chunk.data(), static_cast<size_t>(n));
                continue;
            }
            if (n == 0) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(),
                                    "reading output of " + describe(prog, args));
        }
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            throw std::system_error(errno, std::generic_category(),
                                    "waitpid for " + std::string(prog));
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

std::vector<std::string> concat(const std::vector<std::string>& a,
                                const std::vector<std::string>& b) {
    std::vector<std::string> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

}  // namespace

void run(Tool tool, const std::vector<std::string>& args) {
    spawn_and_wait(binary_for(tool), args, nullptr);
}

std::string run_capture(Tool tool, const std::vector<std::string>& args) {
    std::string output;
    spawn_and_wait(binary_for(tool), args, &output);
    return output;
}

void configure_interface(const std::string& dev, const std::string& cidr, int mtu) {
    run(Tool::ip, {"link", "set", "dev", dev, "mtu", std::to_string(mtu)});

    // Before the link comes up, not after. See the header.
    const std::string disable = "/proc/sys/net/ipv6/conf/" + dev + "/disable_ipv6";
    if (::access(disable.c_str(), F_OK) == 0) {
        write_sysctl(disable, "1");
    } else {
        // A kernel built without IPv6. Nothing to disable, and nothing to leak.
        std::fprintf(stderr, "note: %s does not exist; this kernel has no IPv6\n", disable.c_str());
    }

    run(Tool::ip, {"addr", "add", cidr, "dev", dev});
    run(Tool::ip, {"link", "set", "dev", dev, "up"});
}

bool host_has_ipv6() {
    return !trim(run_capture(Tool::ip, {"-6", "route", "show", "default"})).empty();
}

std::optional<Ipv6Policy> parse_ipv6_policy(std::string_view text) {
    if (text == "refuse") {
        return Ipv6Policy::refuse;
    }
    if (text == "block") {
        return Ipv6Policy::block;
    }
    if (text == "ignore") {
        return Ipv6Policy::ignore;
    }
    return std::nullopt;
}

ChangeSet block_host_ipv6() {
    ChangeSet blocked;
    // Global unicast and unique-local. Link-local (fe80::/10) and multicast are
    // left alone so neighbour discovery on the local segment keeps behaving
    // normally — neither can carry traffic past the first router, so neither is
    // a way around the tunnel.
    for (const char* prefix : {"2000::/3", "fc00::/7"}) {
        const std::vector<std::string> outbound{
            "OUTPUT", "!", "-o", "lo", "-d", prefix,
            "-j", "REJECT", "--reject-with", "adm-prohibited"};
        const std::vector<std::string> inbound{
            "INPUT", "!", "-i", "lo", "-s", prefix, "-j", "DROP"};
        blocked.add(Tool::ip6tables, concat({"-A"}, outbound), concat({"-D"}, outbound));
        blocked.add(Tool::ip6tables, concat({"-A"}, inbound), concat({"-D"}, inbound));
    }
    const std::vector<std::string> forward{"FORWARD", "-j", "DROP"};
    blocked.add(Tool::ip6tables, concat({"-A"}, forward), concat({"-D"}, forward));

    std::fprintf(stderr, "ipv6: global and unique-local traffic blocked for the life of the tunnel\n");
    return blocked;
}

std::optional<std::string> subnet_of(std::string_view cidr) {
    const size_t slash = cidr.find('/');
    if (slash == std::string_view::npos) {
        return std::nullopt;
    }

    const std::string address(cidr.substr(0, slash));
    in_addr parsed{};
    if (::inet_pton(AF_INET, address.c_str(), &parsed) != 1) {
        return std::nullopt;
    }

    const std::string_view prefix_text = cidr.substr(slash + 1);
    unsigned prefix = 0;
    const char* const first = prefix_text.data();
    const char* const last = first + prefix_text.size();
    const auto [ptr, ec] = std::from_chars(first, last, prefix);
    if (ec != std::errc{} || ptr != last || prefix > 32) {
        return std::nullopt;
    }

    // Shifting a uint32_t by 32 is undefined, and prefix 0 is a legal input.
    const uint32_t mask = (prefix == 0) ? 0u : (0xffffffffu << (32 - prefix));
    in_addr network{};
    network.s_addr = ::htonl(::ntohl(parsed.s_addr) & mask);

    std::array<char, INET_ADDRSTRLEN> text{};
    if (::inet_ntop(AF_INET, &network, text.data(), text.size()) == nullptr) {
        return std::nullopt;
    }
    return std::string(text.data()) + "/" + std::to_string(prefix);
}

RouteInfo route_to(const std::string& address) {
    // "10.0.0.1 via 10.1.0.1 dev vpn-c src 10.1.0.2 uid 0" — or without the
    // "via" clause when the destination is on-link.
    const std::string output = run_capture(Tool::ip, {"route", "get", address});

    std::istringstream lines(output);
    std::string line;
    if (!std::getline(lines, line)) {
        throw std::runtime_error("ip route get " + address + ": no output");
    }

    RouteInfo info;
    std::istringstream tokens(line);
    std::string token;
    while (tokens >> token) {
        if (token == "via" && tokens >> token) {
            info.gateway = token;
        } else if (token == "dev" && tokens >> token) {
            info.dev = token;
        }
    }

    if (info.dev.empty()) {
        throw std::runtime_error("could not work out which interface reaches " + address +
                                 " (ip route get said: " + line + ")");
    }
    return info;
}

ScopedCommand::ScopedCommand(Tool tool, const std::vector<std::string>& apply,
                             std::vector<std::string> undo)
    : tool_(tool), undo_(std::move(undo)) {
    try {
        run(tool_, apply);
    } catch (...) {
        // The change never took, so there is nothing to reverse. Clearing this
        // before the exception leaves the scope keeps the destructor quiet.
        undo_.clear();
        throw;
    }
}

ScopedCommand::ScopedCommand(ScopedCommand&& other) noexcept
    : tool_(other.tool_), undo_(std::move(other.undo_)) {
    other.undo_.clear();
}

ScopedCommand::~ScopedCommand() {
    if (undo_.empty()) {
        return;
    }
    try {
        run(tool_, undo_);
    } catch (const std::exception& error) {
        // Nothing useful to do here, but silence would leave the machine in a
        // state nobody was told about.
        std::fprintf(stderr, "warning: could not undo a network change: %s\n", error.what());
    }
}

void ChangeSet::undo_all() noexcept {
    while (!changes_.empty()) {
        changes_.pop_back();
    }
}

ChangeSet& ChangeSet::operator=(ChangeSet&& other) noexcept {
    if (this != &other) {
        undo_all();
        changes_.swap(other.changes_);
    }
    return *this;
}

void ChangeSet::add(Tool tool, const std::vector<std::string>& apply,
                    std::vector<std::string> undo) {
    changes_.emplace_back(tool, apply, std::move(undo));
}

ScopedSysctl::ScopedSysctl(std::string path, const std::string& value) : path_(std::move(path)) {
    {
        std::ifstream in(path_);
        if (!in) {
            throw std::runtime_error("cannot read " + path_);
        }
        std::getline(in, previous_);
    }

    if (previous_ == value) {
        // Already what we want. Leave it, and leave it alone on the way out —
        // another process may be relying on it.
        return;
    }

    std::ofstream out(path_);
    if (!out || !(out << value << '\n') || !out.flush()) {
        throw std::runtime_error("cannot write " + value + " to " + path_);
    }
    active_ = true;
}

ScopedSysctl::ScopedSysctl(ScopedSysctl&& other) noexcept
    : path_(std::move(other.path_)),
      previous_(std::move(other.previous_)),
      active_(other.active_) {
    other.active_ = false;
}

ScopedSysctl& ScopedSysctl::operator=(ScopedSysctl&& other) noexcept {
    if (this != &other) {
        restore();
        path_ = std::move(other.path_);
        previous_ = std::move(other.previous_);
        active_ = other.active_;
        other.active_ = false;
    }
    return *this;
}

ScopedSysctl::~ScopedSysctl() { restore(); }

void ScopedSysctl::restore() noexcept {
    if (!active_) {
        return;
    }
    active_ = false;
    std::ofstream out(path_);
    if (!out || !(out << previous_ << '\n') || !out.flush()) {
        std::fprintf(stderr, "warning: could not restore %s to %s\n", path_.c_str(),
                     previous_.c_str());
    }
}

ChangeSet install_client_routes(const std::string& tun_dev, const std::string& server_address) {
    // Ask before touching anything: once 0.0.0.0/1 is in place the answer to
    // this question is the tunnel itself.
    const RouteInfo underlay = route_to(server_address);

    std::vector<std::string> host_route{server_address + "/32"};
    if (!underlay.gateway.empty()) {
        host_route.insert(host_route.end(), {"via", underlay.gateway});
    }
    host_route.insert(host_route.end(), {"dev", underlay.dev});

    ChangeSet changes;
    changes.add(Tool::ip, concat({"route", "add"}, host_route),
                concat({"route", "del"}, host_route));

    for (const char* half : {"0.0.0.0/1", "128.0.0.0/1"}) {
        const std::vector<std::string> spec{half, "dev", tun_dev};
        changes.add(Tool::ip, concat({"route", "add"}, spec), concat({"route", "del"}, spec));
    }

    std::fprintf(stderr, "routes: %s/32 via %s dev %s, then 0.0.0.0/1 and 128.0.0.0/1 dev %s\n",
                 server_address.c_str(),
                 underlay.gateway.empty() ? "(on-link)" : underlay.gateway.c_str(),
                 underlay.dev.c_str(), tun_dev.c_str());
    return changes;
}

ServerNat install_server_nat(const std::string& tun_dev, const std::string& tun_subnet,
                             const std::string& wan_dev) {
    ScopedSysctl forwarding("/proc/sys/net/ipv4/ip_forward", "1");

    // A rule is a table plus everything from the chain name onwards. Applying it
    // is -A, undoing it is -D with byte-identical arguments — iptables matches
    // the rule by its contents, so this deletes exactly what we added and
    // nothing else. No flushing of tables we do not own.
    struct Rule {
        const char* table;
        std::vector<std::string> spec;
    };
    const Rule rules[] = {
        {"nat", {"POSTROUTING", "-s", tun_subnet, "-o", wan_dev, "-j", "MASQUERADE"}},
        {"filter", {"FORWARD", "-i", tun_dev, "-o", wan_dev, "-s", tun_subnet, "-j", "ACCEPT"}},
        // Return traffic only for flows the client started. An unconditional
        // accept here would let the internet side open connections into the
        // tunnel.
        {"filter",
         {"FORWARD", "-i", wan_dev, "-o", tun_dev, "-d", tun_subnet, "-m", "conntrack",
          "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
    };

    ChangeSet installed;
    for (const Rule& rule : rules) {
        const std::vector<std::string> table{"-t", rule.table};
        installed.add(Tool::iptables, concat(concat(table, {"-A"}), rule.spec),
                      concat(concat(table, {"-D"}), rule.spec));
    }

    std::fprintf(stderr, "nat: forwarding %s between %s and %s, masqueraded\n", tun_subnet.c_str(),
                 tun_dev.c_str(), wan_dev.c_str());
    return ServerNat{std::move(forwarding), std::move(installed)};
}

}  // namespace vpn::netcfg

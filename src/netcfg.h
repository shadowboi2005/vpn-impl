#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Network configuration performed by shelling out to ip(8) and iptables(8),
// plus the RAII guards that undo every change.

namespace vpn::netcfg {

// Which external tool a change is made with.
enum class Tool { ip, iptables, ip6tables };

// Runs the tool with exactly these arguments. The binary is resolved against a
// fixed list of paths and spawned with an empty environment . it is never system(),
// never a formatted command string, never a PATH lookup.
// Throws if the command cannot be run or exits nonzero.
void run(Tool tool, const std::vector<std::string>& args);

// As above, but returns what the command wrote to stdout.
std::string run_capture(Tool tool, const std::vector<std::string>& args);

// Sets MTU, disables IPv6, assigns the address, brings the link up
// IPv6 has to go off before the link comes up: the moment an interface is
// up the kernel gives it a link-local address and emits a router solicitation,
// and on a tunnel device that solicitation goes straight down the tunnel. (It is
// exactly what Phase 1's underlay capture caught.)
//
// No RAII guard on the IPv6 sysctl: the setting lives under the device, and the
// device is ours and disappears with the process.
void configure_interface(const std::string& dev, const std::string& cidr, int mtu);

// "10.9.0.1/24" -> "10.9.0.0/24". Nullopt if the text is not a valid IPv4 CIDR,
// which also makes this the validator for --tun-addr.
std::optional<std::string> subnet_of(std::string_view cidr);

// How the kernel would reach `address` right now
struct RouteInfo {
    std::string dev;
    std::string gateway;  // empty when the destination is on-link
};
RouteInfo route_to(const std::string& address);

// A single change, holding the exact arguments needed to reverse it. The
// constructor applies it; the destructor undoes it. Failure to undo is reported
// on stderr and swallowed — a destructor that throws during unwinding takes the
// process down and leaves the *rest* of the changes in place.
class ScopedCommand {
public:
    ScopedCommand(Tool tool, const std::vector<std::string>& apply,
                  std::vector<std::string> undo);
    ~ScopedCommand();

    ScopedCommand(ScopedCommand&& other) noexcept;
    ScopedCommand(const ScopedCommand&) = delete;
    ScopedCommand& operator=(const ScopedCommand&) = delete;
    ScopedCommand& operator=(ScopedCommand&&) = delete;

    // Keep the change; stop tracking it.
    void release() noexcept { undo_.clear(); }

private:
    Tool tool_;
    std::vector<std::string> undo_;
};

// An ordered set of changes, undone last-first. std::vector does not promise a
// destruction order for its elements, and here the order is part of the
// contract: tunnel routes come out before the host route that kept the
// underlay reachable.
class ChangeSet {
public:
    ChangeSet() = default;
    ~ChangeSet() { undo_all(); }

    ChangeSet(ChangeSet&&) = default;
    ChangeSet& operator=(ChangeSet&& other) noexcept;
    ChangeSet(const ChangeSet&) = delete;
    ChangeSet& operator=(const ChangeSet&) = delete;

    void add(Tool tool, const std::vector<std::string>& apply, std::vector<std::string> undo);
    [[nodiscard]] size_t size() const noexcept { return changes_.size(); }

private:
    void undo_all() noexcept;

    std::vector<ScopedCommand> changes_;
};

// Sets a /proc/sys value and puts the old one back on destruction.
class ScopedSysctl {
public:
    ScopedSysctl() = default;  // inert
    ScopedSysctl(std::string path, const std::string& value);
    ~ScopedSysctl();

    ScopedSysctl(ScopedSysctl&& other) noexcept;
    ScopedSysctl& operator=(ScopedSysctl&& other) noexcept;
    ScopedSysctl(const ScopedSysctl&) = delete;
    ScopedSysctl& operator=(const ScopedSysctl&) = delete;

private:
    void restore() noexcept;

    std::string path_;
    std::string previous_;
    bool active_ = false;
};

// Client: full-tunnel routing.
//
// Installs, strictly in this order:
//   1. <server_address>/32 via the gateway that reaches it today
//   2. 0.0.0.0/1   dev <tun_dev>
//   3. 128.0.0.0/1 dev <tun_dev>
//
// Step 1 has to come first. Without it, step 2 captures the encrypted UDP
// packets destined for the server and feeds them back into the tunnel — a
// routing loop that looks exactly like "the VPN doesn't work at all".
//
// The original default route is left alone. 0.0.0.0/1 and 128.0.0.0/1 together
// cover the whole address space at a longer prefix, so they win
// longest-prefix-match without anything being deleted.
ChangeSet install_client_routes(const std::string& tun_dev, const std::string& server_address);

// True if this host can currently send IPv6 off-link, judged by whether it has a
// default IPv6 route. A link-local-only stack cannot reach the internet and so
// is not a way around the tunnel; a default route is.
bool host_has_ipv6();

// What to do about a host that has working IPv6 while a v4-only tunnel is up.
// Silent v6 leakage around a v4 tunnel is a total bypass, so there is no
// "do nothing quietly" option — `ignore` still says so on stderr.
enum class Ipv6Policy { refuse, block, ignore };

// Parses "refuse" / "block" / "ignore".
std::optional<Ipv6Policy> parse_ipv6_policy(std::string_view text);

// Rejects outbound global and unique-local IPv6 and drops it inbound, leaving
// link-local and loopback alone. Rejecting rather than dropping outbound means
// applications fail immediately and fall back to IPv4 instead of hanging for a
// connect timeout on every name that resolves to a AAAA record.
ChangeSet block_host_ipv6();

// Server: forward and masquerade traffic from the tunnel subnet.
struct ServerNat {
    ScopedSysctl ip_forward;
    ChangeSet rules;
};
ServerNat install_server_nat(const std::string& tun_dev, const std::string& tun_subnet,
                             const std::string& wan_dev);

}  // namespace vpn::netcfg

#pragma once

#include <string>
#include <vector>

// Network configuration performed by shelling out to ip(8).

namespace vpn::netcfg {

// Runs ip(8) with exactly these arguments. The binary is resolved against a
// fixed list of paths and spawned with an empty environment — never system(),
// never a formatted command string, never a PATH lookup.
// Throws if the command cannot be run or exits nonzero.
void run_ip(const std::vector<std::string>& args);

// ip link set dev DEV mtu MTU; ip addr add CIDR dev DEV; ip link set dev DEV up
void configure_interface(const std::string& dev, const std::string& cidr, int mtu);

}  // namespace vpn::netcfg

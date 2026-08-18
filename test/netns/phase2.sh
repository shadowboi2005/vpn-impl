#!/bin/bash
# Phase 2 acceptance test: full-tunnel routing and NAT.
#
#  client ns          router ns              server ns            internet ns
#  10.1.0.2/24 ─veth─ 10.1.0.1/24
#                     10.0.0.2/24 ──veth──  10.0.0.1/24
#                                           192.168.100.1/24 ─veth─ 192.168.100.2/24
#  tun0 10.9.0.2/24                         tun0 10.9.0.1/24
#
# The router namespace is the point of this topology. It puts the VPN server one
# hop away from the client, so the client's underlay traffic has to leave via a
# *gateway*. That is the only arrangement in which the routing loop PLAN.md warns
# about can actually happen: without the <server>/32 host route, the encrypted
# UDP matches 0.0.0.0/1 dev tun0 and gets fed back into the tunnel.
#
# The internet namespace stands in for the public internet. It runs a three-line
# HTTP server that echoes the source address it sees — a local ifconfig.me. If
# NAT is working, the client asking it "what is my address?" gets the server's
# WAN address back, not the client's tunnel address.
#
# Needs root. Nothing here touches the host's own networking: every interface,
# route, iptables rule and sysctl lives inside a namespace that is deleted on
# exit.
#
#   sudo test/netns/phase2.sh          run the test and clean up
#   sudo test/netns/phase2.sh --keep   leave the namespaces up afterwards
#   sudo test/netns/phase2.sh --clean  just tear down a previous --keep run

set -uo pipefail

CLIENT_NS=vpn-client
ROUTER_NS=vpn-router
SERVER_NS=vpn-server
NET_NS=vpn-net
PORT=51820
MTU=1420
WEB_PORT=8080

SERVER_UNDERLAY=10.0.0.1
SERVER_WAN=192.168.100.1
INTERNET=192.168.100.2

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_dir=${VPN_BUILD_DIR:-$repo_root/build/debug}
vpnd=$build_dir/vpnd
vpn=$build_dir/vpn
vpnkey=$build_dir/vpnkey
logdir=${VPN_LOG_DIR:-$repo_root/build/phase2-logs}

keep=0
clean_only=0
for arg in "$@"; do
    case $arg in
        --keep) keep=1 ;;
        --clean) clean_only=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done


# Keys. Generated fresh per run and thrown away with the log directory; the
# tunnel refuses to start without them, which is the point of Phase 5.
gen_keys() {
    "$vpnkey" genkey > "$logdir/client.key" && chmod 600 "$logdir/client.key"
    "$vpnkey" genkey > "$logdir/server.key" && chmod 600 "$logdir/server.key"
    "$vpnkey" pubkey < "$logdir/client.key" > "$logdir/client.pub"
    "$vpnkey" pubkey < "$logdir/server.key" > "$logdir/server.pub"
    CLIENT_PUB=$(cat "$logdir/client.pub")
    SERVER_PUB=$(cat "$logdir/server.pub")
    [ -n "$CLIENT_PUB" ] && [ -n "$SERVER_PUB" ] || fail "key generation failed"
}

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

teardown() {
    for ns in "$CLIENT_NS" "$ROUTER_NS" "$SERVER_NS" "$NET_NS"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
    done
    sleep 0.2
    for ns in "$CLIENT_NS" "$ROUTER_NS" "$SERVER_NS" "$NET_NS"; do
        ip netns del "$ns" 2>/dev/null
    done
}

[ "$(id -u)" -eq 0 ] || fail "must run as root (sudo $0)"

if [ "$clean_only" -eq 1 ]; then
    teardown
    echo "namespaces removed"
    exit 0
fi

[ -x "$vpnd" ] || fail "$vpnd not found — run: cmake --preset debug && cmake --build build/debug"
[ -x "$vpnkey" ] || fail "$vpnkey not found — run: cmake --build build/debug"
[ -x "$vpn" ]  || fail "$vpn not found — run: cmake --preset debug && cmake --build build/debug"
command -v python3 >/dev/null || fail "python3 is needed for the stand-in web server"
command -v curl    >/dev/null || fail "curl is needed"

mkdir -p "$logdir"
rm -f "$logdir"/*.log "$logdir"/*.txt "$logdir"/*.pcap

teardown  # any leftovers from an interrupted run

# ---------------------------------------------------------------- topology ---

gen_keys

say "building the topology"
for ns in "$CLIENT_NS" "$ROUTER_NS" "$SERVER_NS" "$NET_NS"; do
    ip netns add "$ns" || fail "ip netns add $ns"
    ip -n "$ns" link set lo up
done
if [ "$keep" -eq 0 ]; then
    trap teardown EXIT
fi

link() {  # link <ns-a> <if-a> <cidr-a> <ns-b> <if-b> <cidr-b>
    ip link add "$2" type veth peer name "$5" || fail "veth $2 <-> $5"
    ip link set "$2" netns "$1"
    ip link set "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2"
    ip -n "$1" link set "$2" up
    ip -n "$4" addr add "$6" dev "$5"
    ip -n "$4" link set "$5" up
}

link "$CLIENT_NS" vpn-c  10.1.0.2/24      "$ROUTER_NS" vpn-r1 10.1.0.1/24
link "$ROUTER_NS" vpn-r2 10.0.0.2/24      "$SERVER_NS" vpn-s  10.0.0.1/24
link "$SERVER_NS" vpn-sw 192.168.100.1/24 "$NET_NS"    vpn-i  192.168.100.2/24

# The client reaches everything through the router — including the VPN server.
ip -n "$CLIENT_NS" route add default via 10.1.0.1
ip netns exec "$ROUTER_NS" sysctl -qw net.ipv4.ip_forward=1
# The server's replies to the client's underlay go back through the router; its
# default route points at the "internet" side, which is what --wan-if autodetect
# will find.
ip -n "$SERVER_NS" route add 10.1.0.0/24 via 10.0.0.2
ip -n "$SERVER_NS" route add default via "$INTERNET"
# A fresh namespace forwards everything by default, which would let this test
# pass without the daemon's FORWARD rules doing any work. Make them load-bearing.
ip netns exec "$SERVER_NS" iptables -P FORWARD DROP
# A new namespace copies ipv4_devconf from the init namespace when it is
# created, so on a host that already forwards (docker, libvirt, a router) it
# starts at 1. ScopedSysctl correctly leaves a value that is already what it
# wants alone — which would mean this test never exercised the set/restore path
# at all. Force it off so it has to.
ip netns exec "$SERVER_NS" sysctl -qw net.ipv4.ip_forward=0

say "sanity: the underlay works before the VPN exists"
ip netns exec "$CLIENT_NS" ping -c 1 -W 2 "$SERVER_UNDERLAY" >/dev/null \
    || fail "client cannot reach the server through the router"
note "10.1.0.2 -> $SERVER_UNDERLAY via 10.1.0.1: ok"

# ------------------------------------------------------- stand-in internet ---

cat >"$logdir/whoami.py" <<'PY'
import http.server


class Handler(http.server.BaseHTTPRequestHandler):
    """Reports the source address it sees. A local ifconfig.me."""

    def do_GET(self):
        body = self.client_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
PY

ip netns exec "$NET_NS" python3 "$logdir/whoami.py" >"$logdir/whoami.log" 2>&1 &
web_pid=$!
sleep 0.7
kill -0 "$web_pid" 2>/dev/null || { cat "$logdir/whoami.log"; fail "stand-in web server died"; }

say "baseline: who does the internet think the *server* is"
direct=$(ip netns exec "$SERVER_NS" curl -s --max-time 5 "http://$INTERNET:$WEB_PORT/")
note "server asking directly: $direct"
[ "$direct" = "$SERVER_WAN" ] || fail "expected $SERVER_WAN, got '$direct'"

# --------------------------------------------------------------- the tunnel ---

export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1
export UBSAN_OPTIONS=print_stacktrace=1

ip -n "$CLIENT_NS" route show | sort >"$logdir/client-routes-before.txt"
ip netns exec "$SERVER_NS" iptables-save >"$logdir/server-iptables-before.txt" 2>/dev/null
server_forward_before=$(ip netns exec "$SERVER_NS" cat /proc/sys/net/ipv4/ip_forward)
note "server ip_forward before: $server_forward_before"

start_tunnel() {
    ip netns exec "$SERVER_NS" "$vpnd" \
        --dev tun0 --tun-addr 10.9.0.1/24 --mtu "$MTU" --listen-port "$PORT" \
        --private-key "$logdir/server.key" --peer-key "$CLIENT_PUB" \
        >"$logdir/vpnd.log" 2>&1 &
    vpnd_pid=$!

    ip netns exec "$CLIENT_NS" "$vpn" \
        --dev tun0 --tun-addr 10.9.0.2/24 --mtu "$MTU" --server "$SERVER_UNDERLAY:$PORT" \
        --private-key "$logdir/client.key" --peer-key "$SERVER_PUB" \
        >"$logdir/vpn.log" 2>&1 &
    vpn_pid=$!

    for _ in $(seq 1 50); do
        if ip -n "$CLIENT_NS" route show | grep -q '^0.0.0.0/1 ' &&
           ip netns exec "$SERVER_NS" iptables -t nat -S POSTROUTING | grep -q MASQUERADE; then
            # Routes and rules are up; the session still needs a first packet to
            # trigger the handshake, since this initiates on demand.
            ip netns exec "$CLIENT_NS" ping -c 1 -W 2 10.9.0.1 >/dev/null 2>&1
            grep -q "session established" "$logdir/vpnd.log" 2>/dev/null && return 0
        fi
        kill -0 "$vpnd_pid" 2>/dev/null || return 1
        kill -0 "$vpn_pid"  2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

say "starting the tunnel with routing and NAT"
start_tunnel || { cat "$logdir/vpnd.log" "$logdir/vpn.log"; fail "tunnel did not come up"; }
note "$(grep '^nat:' "$logdir/vpnd.log")"
note "$(grep '^routes:' "$logdir/vpn.log")"
server_forward_during=$(ip netns exec "$SERVER_NS" cat /proc/sys/net/ipv4/ip_forward)
note "server ip_forward while the tunnel is up: $server_forward_during"

say "the routing loop PLAN.md warns about"
route_to_server=$(ip netns exec "$CLIENT_NS" ip route get "$SERVER_UNDERLAY")
note "$route_to_server"
if grep -q 'dev tun0' <<<"$route_to_server"; then
    loop_ok=0
    note "the underlay now points into the tunnel — this is the loop"
else
    loop_ok=1
    note "underlay still leaves via the physical interface: no loop"
fi

say "client routing table with the tunnel up"
ip -n "$CLIENT_NS" route show | sed 's/^/   /'

# ------------------------------------------------------------ the real test ---

# Starting a capture is not instant: tcpdump has to open the device, set
# promiscuous mode and build the filter program, and a fixed sleep is a guess
# about how long that takes. It announces "listening on ..." when it is actually
# ready, so wait for that instead. Its stderr goes to a file rather than
# /dev/null, because on exit it prints how many packets it captured and how many
# the kernel dropped — which is the difference between "saw nothing" and "saw
# them and lost them", and throwing it away turns a diagnosis into a guess.
capture_pid=""
start_capture() {  # <ns> <iface> <pcap> <log> <filter>
    ip netns exec "$1" tcpdump -i "$2" -n -U --immediate-mode -w "$3" "$5" >"$4" 2>&1 &
    capture_pid=$!
    for _ in $(seq 1 80); do
        grep -q "listening on" "$4" 2>/dev/null && return 0
        kill -0 "$capture_pid" 2>/dev/null || break
        sleep 0.1
    done
    printf '\033[31mtcpdump on %s in %s never became ready\033[0m\n' "$2" "$1" >&2
    sed 's/^/   /' "$4" >&2
    return 1
}

say "capturing on the internet side while the client asks who it is"
start_capture "$NET_NS" vpn-i "$logdir/internet.pcap" "$logdir/tcpdump-internet.txt" \
    "tcp port $WEB_PORT" || true
tcpdump_pid=$capture_pid
# Also watch the underlay, to see what the tunnel itself is carrying.
start_capture "$CLIENT_NS" vpn-c "$logdir/underlay.pcap" "$logdir/tcpdump-underlay.txt" \
    "udp port $PORT" || true
underlay_pid=$capture_pid

seen=$(ip netns exec "$CLIENT_NS" curl -s --max-time 8 "http://$INTERNET:$WEB_PORT/")
curl_rc=$?
note "the internet sees the client as: '${seen:-<nothing>}'"

sleep 0.5
# SIGINT rather than SIGTERM: it is the signal tcpdump answers by flushing and
# printing its capture statistics.
kill -INT "$tcpdump_pid" "$underlay_pid" 2>/dev/null
wait "$tcpdump_pid" 2>/dev/null
wait "$underlay_pid" 2>/dev/null

say "what tcpdump itself says it saw"
note "internet side: $(grep -E 'packets (captured|received|dropped)' "$logdir/tcpdump-internet.txt" | tr '\n' ' ')"
note "underlay:      $(grep -E 'packets (captured|received|dropped)' "$logdir/tcpdump-underlay.txt" | tr '\n' ' ')"

nat_ok=0
if [ "$curl_rc" -eq 0 ] && [ "$seen" = "$SERVER_WAN" ]; then
    nat_ok=1
fi

say "independent confirmation from the capture"
tcpdump -r "$logdir/internet.pcap" -n -c 4 2>/dev/null | sed 's/^/   /'
internet_total=$(tcpdump -r "$logdir/internet.pcap" -n 2>/dev/null | wc -l)
leaked=$(tcpdump -r "$logdir/internet.pcap" -n 2>/dev/null | grep -c '10\.9\.0\.')
note "$internet_total packets captured on the internet side, $leaked carrying a tunnel address"
# "Nothing leaked" out of an empty capture is not evidence of anything. A single
# HTTP request over TCP is a handshake, a request, a response and a teardown, so
# anything below this means the capture missed traffic rather than that there
# was none.
[ "$internet_total" -ge 6 ] || note "WARNING: the capture looks truncated"

say "a bigger transfer, to exercise something other than a single small request"
bulk=$(ip netns exec "$CLIENT_NS" curl -s --max-time 8 -o /dev/null -w '%{http_code} %{size_download}' \
       "http://$INTERNET:$WEB_PORT/" 2>&1)
note "second request: $bulk"

say "MTU through the tunnel: $((MTU - 28))-byte payload, do-not-fragment"
if ip netns exec "$CLIENT_NS" ping -c 2 -W 2 -M do -s "$((MTU - 28))" 10.9.0.1 >/dev/null; then
    mtu_ok=1
else
    mtu_ok=0
fi
note "large packets: $([ $mtu_ok -eq 1 ] && echo ok || echo FAILED)"

say "IPv6 on the tunnel interface"
tun_v6_client=$(ip -n "$CLIENT_NS" -6 addr show dev tun0 2>/dev/null | grep -c inet6)
tun_v6_server=$(ip -n "$SERVER_NS" -6 addr show dev tun0 2>/dev/null | grep -c inet6)
note "IPv6 addresses on tun0: client $tun_v6_client, server $tun_v6_server (want 0 and 0)"
note "disable_ipv6 on the client's tun0: $(ip netns exec "$CLIENT_NS" cat /proc/sys/net/ipv6/conf/tun0/disable_ipv6 2>/dev/null)"

say "Phase 3 framing, read off the wire"
# The UDP payload is a transport-data message now, not a raw IP packet:
#
#   udp[8]        message type, must be 4
#   udp[9..11]    reserved, must be zero
#   udp[12..15]   receiver_index
#   udp[16..23]   counter
#   udp[24...]    the padded inner packet
#
# Asserting the type and reserved bytes here checks the encoder against
# something that is not the decoder, which is the one thing the unit tests and
# the fuzzer cannot do for each other.
udp_total=$(tcpdump -r "$logdir/underlay.pcap" -n 2>/dev/null | wc -l)
framed=$(tcpdump -r "$logdir/underlay.pcap" -n \
    "udp[8] >= 1 and udp[8] <= 4 and udp[9] = 0 and udp[10] = 0 and udp[11] = 0" 2>/dev/null | wc -l)
note "$framed of $udp_total datagrams carry a well-formed transport-data header"
echo "   first datagram, header and inner packet:"
tcpdump -r "$logdir/underlay.pcap" -n -c 1 -X 2>/dev/null | head -8 | sed 's/^/   /'

# Phase 1's capture caught tun0's own router solicitation being encapsulated and
# sent down the tunnel. The inner packet's first nibble is its IP version: 4 is
# what belongs here, 6 is the leak.
# Since Phase 5 the inner packet is ciphertext, so it can no longer be read off
# the wire. What tun0 carries is checked at the interface instead.
v6_inside=$(ip netns exec "$CLIENT_NS" cat /proc/net/dev_snmp6/tun0 2>/dev/null \
    | awk '/Ip6OutRequests/ {print $2}')
v6_inside=${v6_inside:-0}
note "IPv6 packets tun0 tried to send: $v6_inside (want 0)"

say "iptables counters on the server"
ip netns exec "$SERVER_NS" iptables -t nat -L POSTROUTING -n -v | sed 's/^/   /'
ip netns exec "$SERVER_NS" iptables -L FORWARD -n -v | sed 's/^/   /'

# ------------------------------------------------------------ SIGINT teardown ---

say "SIGINT: everything installed must come back out"
kill -INT "$vpnd_pid" "$vpn_pid" 2>/dev/null
wait "$vpnd_pid"; vpnd_rc=$?
wait "$vpn_pid";  vpn_rc=$?
note "vpnd exited $vpnd_rc, vpn exited $vpn_rc"

ip -n "$CLIENT_NS" route show | sort >"$logdir/client-routes-after.txt"
ip netns exec "$SERVER_NS" iptables-save >"$logdir/server-iptables-after.txt" 2>/dev/null
server_forward_after=$(ip netns exec "$SERVER_NS" cat /proc/sys/net/ipv4/ip_forward)

routes_restored=1
if ! diff -u "$logdir/client-routes-before.txt" "$logdir/client-routes-after.txt" >"$logdir/route-diff.txt"; then
    routes_restored=0
    note "client routing table did NOT come back:"
    sed 's/^/   /' "$logdir/route-diff.txt"
else
    note "client routing table is byte-identical to before the VPN started"
fi

rules_removed=1
if ip netns exec "$SERVER_NS" iptables-save | grep -qE 'MASQUERADE|10\.9\.0\.0/24'; then
    rules_removed=0
    note "iptables rules left behind:"
    ip netns exec "$SERVER_NS" iptables-save | grep -E 'MASQUERADE|10\.9\.0\.0/24' | sed 's/^/   /'
else
    note "every iptables rule we added is gone"
fi

forward_restored=1
if [ "$server_forward_after" != "$server_forward_before" ]; then
    forward_restored=0
fi
note "server ip_forward: $server_forward_before before, $server_forward_after after"

say "normal networking still works after teardown"
if ip netns exec "$CLIENT_NS" ping -c 2 -W 2 "$SERVER_UNDERLAY" >/dev/null; then
    after_ok=1
else
    after_ok=0
fi
note "client -> $SERVER_UNDERLAY: $([ $after_ok -eq 1 ] && echo ok || echo FAILED)"

# -------------------------------------------------- host IPv6 leak policy ---
#
# Give the client namespace working IPv6 — a global address, a neighbour to talk
# to, and a default route — and check that a v4-only tunnel refuses to hide the
# bypass.

say "host IPv6: giving the client a working v6 stack"
ip -n "$CLIENT_NS" addr add 2001:db8:1::2/64 dev vpn-c
ip -n "$ROUTER_NS" addr add 2001:db8:1::1/64 dev vpn-r1
ip -n "$CLIENT_NS" -6 route add default dev vpn-c
sleep 1.5  # duplicate address detection
if ip netns exec "$CLIENT_NS" ping -6 -c 2 -W 2 2001:db8:1::1 >/dev/null 2>&1; then
    v6_before=1
else
    v6_before=0
fi
note "client can reach 2001:db8:1::1 over IPv6: $([ $v6_before -eq 1 ] && echo yes || echo no)"

say "default policy must refuse to start rather than leak"
ip netns exec "$CLIENT_NS" "$vpn" \
    --dev tun0 --tun-addr 10.9.0.2/24 --mtu "$MTU" --server "$SERVER_UNDERLAY:$PORT" \
    --private-key "$logdir/client.key" --peer-key "$SERVER_PUB" \
    >"$logdir/vpn-refuse.log" 2>&1
refuse_rc=$?
sed 's/^/   /' "$logdir/vpn-refuse.log"
refuse_ok=0
if [ "$refuse_rc" -ne 0 ] && grep -q "default IPv6 route" "$logdir/vpn-refuse.log"; then
    refuse_ok=1
fi
note "refused with rc=$refuse_rc: $([ $refuse_ok -eq 1 ] && echo "as expected" || echo "NOT as expected")"
# Refusing must leave nothing behind — it happens before the TUN device exists.
refuse_clean=1
ip -n "$CLIENT_NS" link show tun0 >/dev/null 2>&1 && { refuse_clean=0; note "a tun0 was left behind"; }
ip -n "$CLIENT_NS" route show | sort | diff -q - "$logdir/client-routes-before.txt" >/dev/null \
    || { refuse_clean=0; note "routes were left behind"; }
note "nothing left behind by the refusal: $([ $refuse_clean -eq 1 ] && echo yes || echo NO)"

say "--host-ipv6 block: bring the tunnel up with v6 firewalled off"
ip netns exec "$SERVER_NS" "$vpnd" \
    --dev tun0 --tun-addr 10.9.0.1/24 --mtu "$MTU" --listen-port "$PORT" \
    --private-key "$logdir/server.key" --peer-key "$CLIENT_PUB" \
    >"$logdir/vpnd-v6.log" 2>&1 &
vpnd6_pid=$!
ip netns exec "$CLIENT_NS" "$vpn" \
    --dev tun0 --tun-addr 10.9.0.2/24 --mtu "$MTU" --server "$SERVER_UNDERLAY:$PORT" \
    --private-key "$logdir/client.key" --peer-key "$SERVER_PUB" --host-ipv6 block >"$logdir/vpn-block.log" 2>&1 &
vpn6_pid=$!

for _ in $(seq 1 50); do
    ip netns exec "$CLIENT_NS" ip6tables -S OUTPUT 2>/dev/null | grep -q REJECT && break
    sleep 0.1
done
# The handshake is on demand, so the session needs a packet to trigger it.
# Without this the curl below would spend its first SYN doing that, and a slow
# retransmit would look like a broken tunnel.
for _ in $(seq 1 30); do
    ip netns exec "$CLIENT_NS" ping -c 1 -W 1 10.9.0.1 >/dev/null 2>&1
    grep -q "session established" "$logdir/vpnd-v6.log" 2>/dev/null && break
    sleep 0.2
done
echo "   ip6tables in the client namespace:"
ip netns exec "$CLIENT_NS" ip6tables -S | sed 's/^/     /'

if ip netns exec "$CLIENT_NS" ping -6 -c 2 -W 2 2001:db8:1::1 >/dev/null 2>&1; then
    v6_during=1
else
    v6_during=0
fi
note "IPv6 reachable while blocked: $([ $v6_during -eq 1 ] && echo "yes — LEAK" || echo "no")"

# The v4 tunnel must still work with the v6 block in place.
seen6=$(ip netns exec "$CLIENT_NS" curl -s --max-time 8 "http://$INTERNET:$WEB_PORT/")
note "v4 through the tunnel while v6 is blocked: '${seen6:-<nothing>}'"

kill -INT "$vpnd6_pid" "$vpn6_pid" 2>/dev/null
wait "$vpnd6_pid"; vpnd6_rc=$?
wait "$vpn6_pid";  vpn6_rc=$?

v6_rules_left=$(ip netns exec "$CLIENT_NS" ip6tables -S | grep -cE '^-A ')
if ip netns exec "$CLIENT_NS" ping -6 -c 2 -W 2 2001:db8:1::1 >/dev/null 2>&1; then
    v6_after=1
else
    v6_after=0
fi
note "after SIGINT: $v6_rules_left ip6tables rules left, IPv6 reachable again: $([ $v6_after -eq 1 ] && echo yes || echo no)"

ip -n "$CLIENT_NS" -6 route del default dev vpn-c 2>/dev/null
ip -n "$CLIENT_NS" addr del 2001:db8:1::2/64 dev vpn-c 2>/dev/null

# ------------------------------------------------------------- SIGKILL case ---

say "SIGKILL: what is left behind when destructors never run"
if start_tunnel; then
    kill -9 "$vpnd_pid" "$vpn_pid" 2>/dev/null
    wait "$vpnd_pid" 2>/dev/null
    wait "$vpn_pid" 2>/dev/null
    sleep 0.5

    echo "   client routes after SIGKILL, against the pre-VPN baseline:"
    ip -n "$CLIENT_NS" route show | sort >"$logdir/client-routes-sigkill.txt"
    diff -u "$logdir/client-routes-before.txt" "$logdir/client-routes-sigkill.txt" \
        | tail -n +3 | sed 's/^/   /' || true
    echo "   server iptables after SIGKILL:"
    ip netns exec "$SERVER_NS" iptables-save | grep -E 'MASQUERADE|10\.9\.0\.0/24' \
        | sed 's/^/   /' || echo "   (none)"
    echo "   server ip_forward after SIGKILL: $(ip netns exec "$SERVER_NS" cat /proc/sys/net/ipv4/ip_forward)"
    note "this is a documented limitation, not a bug to fix: SIGKILL cannot be caught."

    # Put the namespace back the way we found it so nothing above is confused.
    ip netns exec "$SERVER_NS" iptables -t nat -F POSTROUTING 2>/dev/null
    ip netns exec "$SERVER_NS" iptables -F FORWARD 2>/dev/null
    ip -n "$CLIENT_NS" route del "$SERVER_UNDERLAY/32" via 10.1.0.1 dev vpn-c 2>/dev/null
else
    note "could not restart the tunnel for the SIGKILL case (see logs)"
fi

kill "$web_pid" 2>/dev/null
wait "$web_pid" 2>/dev/null

# ------------------------------------------------------------------ verdict ---

say "daemon logs"
echo "--- vpnd ---"; sed 's/^/   /' "$logdir/vpnd.log"
echo "--- vpn  ---"; sed 's/^/   /' "$logdir/vpn.log"

san_hits=$(grep -lE "AddressSanitizer|runtime error|LeakSanitizer" "$logdir"/*.log 2>/dev/null)

say "result"
status=0
[ "$nat_ok" -eq 1 ]           || { echo "the internet did not see the server's address (got '$seen')"; status=1; }
[ "$leaked" -eq 0 ]           || { echo "$leaked packets leaked a 10.9.0.x address past the NAT"; status=1; }
[ "$loop_ok" -eq 1 ]          || { echo "the underlay route points into the tunnel — routing loop"; status=1; }
[ "$mtu_ok" -eq 1 ]           || { echo "large ping through the tunnel FAILED"; status=1; }
[ "$routes_restored" -eq 1 ]  || { echo "client routes not restored on SIGINT"; status=1; }
[ "$rules_removed" -eq 1 ]    || { echo "iptables rules not removed on SIGINT"; status=1; }
[ "$server_forward_before" = "0" ]  || { echo "test setup: ip_forward should start at 0, was $server_forward_before"; status=1; }
[ "$server_forward_during" = "1" ]  || { echo "ip_forward was $server_forward_during with the tunnel up, expected 1"; status=1; }
[ "$forward_restored" -eq 1 ] || { echo "ip_forward not restored on SIGINT"; status=1; }
[ "$after_ok" -eq 1 ]         || { echo "networking broken after teardown"; status=1; }
[ "$vpnd_rc" -eq 0 ]          || { echo "vpnd exited $vpnd_rc, expected 0"; status=1; }
[ "$vpn_rc" -eq 0 ]           || { echo "vpn exited $vpn_rc, expected 0"; status=1; }
[ "$tun_v6_client" -eq 0 ]    || { echo "client tun0 has $tun_v6_client IPv6 addresses"; status=1; }
[ "$tun_v6_server" -eq 0 ]    || { echo "server tun0 has $tun_v6_server IPv6 addresses"; status=1; }
[ "$v6_inside" -eq 0 ]        || { echo "$v6_inside IPv6 packets were carried inside the tunnel"; status=1; }
[ "$udp_total" -ge 6 ]        || { echo "only $udp_total datagrams captured on the underlay — too few to conclude anything"; status=1; }
[ "$internet_total" -ge 6 ]   || { echo "only $internet_total packets captured on the internet side — the leak check would be vacuous"; status=1; }
[ "$framed" -eq "$udp_total" ] || { echo "$((udp_total - framed)) datagrams were not well-formed transport-data messages"; status=1; }
[ "$v6_before" -eq 1 ]        || { echo "the IPv6 test setup itself does not work"; status=1; }
[ "$refuse_ok" -eq 1 ]        || { echo "the client did not refuse to start on an IPv6-capable host"; status=1; }
[ "$refuse_clean" -eq 1 ]     || { echo "refusing to start left state behind"; status=1; }
[ "$v6_during" -eq 0 ]        || { echo "IPv6 still reachable with --host-ipv6 block — leak"; status=1; }
[ "$seen6" = "$SERVER_WAN" ]  || { echo "v4 tunnel broken while v6 blocked (got '$seen6')"; status=1; }
[ "$v6_rules_left" -eq 0 ]    || { echo "$v6_rules_left ip6tables rules left after SIGINT"; status=1; }
[ "$v6_after" -eq 1 ]         || { echo "IPv6 did not come back after teardown"; status=1; }
[ "$vpnd6_rc" -eq 0 ]         || { echo "vpnd (v6 run) exited $vpnd6_rc, expected 0"; status=1; }
[ "$vpn6_rc" -eq 0 ]          || { echo "vpn (v6 run) exited $vpn6_rc, expected 0"; status=1; }
[ -z "$san_hits" ]            || { echo "sanitizer output in: $san_hits"; status=1; }

if [ "$status" -eq 0 ]; then
    printf '\033[32mPHASE 2 PASS\033[0m — traffic exits via the server, teardown is complete\n'
else
    printf '\033[31mPHASE 2 FAIL\033[0m — see above; logs in %s\n' "$logdir"
fi

if [ "$keep" -eq 1 ]; then
    echo
    echo "namespaces kept. poke at them with:"
    echo "  sudo ip netns exec $CLIENT_NS bash"
    echo "  sudo $0 --clean    # when you are done"
fi

exit "$status"

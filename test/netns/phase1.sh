#!/bin/bash
# Phase 1 acceptance test: packets flow both ways through the tunnel.
#
# Kept as the smallest end-to-end test in the tree. Since Phase 5 the tunnel
# is encrypted, so this also checks that nothing it carries is readable on
# the wire; the replay and forgery tests live in phase5.sh.
#
#   client ns  10.0.0.2/24 ──veth── 10.0.0.1/24  server ns
#     tun0 10.9.0.2/24                 tun0 10.9.0.1/24
#
# Needs root: creating namespaces, veth pairs and TUN devices all require
# CAP_NET_ADMIN. Nothing here touches the host's own networking — every
# interface lives inside a namespace that is deleted on exit.
#
#   sudo test/netns/phase1.sh          run the test and clean up
#   sudo test/netns/phase1.sh --keep   leave the namespaces up afterwards
#   sudo test/netns/phase1.sh --clean  just tear down a previous --keep run

set -uo pipefail

CLIENT_NS=vpn-client
SERVER_NS=vpn-server
PORT=51820
MTU=1420

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_dir=${VPN_BUILD_DIR:-$repo_root/build/debug}
vpnd=$build_dir/vpnd
vpn=$build_dir/vpn
vpnkey=$build_dir/vpnkey
logdir=${VPN_LOG_DIR:-$repo_root/build/phase1-logs}

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
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

teardown() {
    ip netns pids "$CLIENT_NS" 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns pids "$SERVER_NS" 2>/dev/null | xargs -r kill 2>/dev/null
    sleep 0.2
    ip netns del "$CLIENT_NS" 2>/dev/null
    ip netns del "$SERVER_NS" 2>/dev/null
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

mkdir -p "$logdir"
rm -f "$logdir"/*.log "$logdir"/*.txt "$logdir"/*.pcap

# Any leftovers from an interrupted run.
teardown

gen_keys

say "creating namespaces"
ip netns add "$CLIENT_NS" || fail "ip netns add $CLIENT_NS"
ip netns add "$SERVER_NS" || fail "ip netns add $SERVER_NS"
if [ "$keep" -eq 0 ]; then
    trap teardown EXIT
fi

ip link add vpn-c type veth peer name vpn-s || fail "creating the veth pair"
ip link set vpn-c netns "$CLIENT_NS"
ip link set vpn-s netns "$SERVER_NS"

ip -n "$CLIENT_NS" addr add 10.0.0.2/24 dev vpn-c
ip -n "$CLIENT_NS" link set vpn-c up
ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" addr add 10.0.0.1/24 dev vpn-s
ip -n "$SERVER_NS" link set vpn-s up
ip -n "$SERVER_NS" link set lo up

say "sanity: the underlay itself works"
ip netns exec "$CLIENT_NS" ping -c 1 -W 2 10.0.0.1 >/dev/null || fail "veth link is dead"
echo "10.0.0.2 -> 10.0.0.1 ok"

# UBSan aborts rather than continuing, so any undefined behaviour shows up as a
# dead daemon and a failed ping rather than a line nobody reads.
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1
export UBSAN_OPTIONS=print_stacktrace=1

say "starting the tunnel"
# --no-nat / --no-routes keep this a Phase 1 test: a bare tunnel and nothing
# else. Phase 2's routing and NAT get their own harness.
ip netns exec "$SERVER_NS" "$vpnd" \
    --dev tun0 --tun-addr 10.9.0.1/24 --mtu "$MTU" --listen-port "$PORT" --no-nat \
    --private-key "$logdir/server.key" --peer-key "$CLIENT_PUB" \
    >"$logdir/vpnd.log" 2>&1 &
vpnd_pid=$!

ip netns exec "$CLIENT_NS" "$vpn" \
    --dev tun0 --tun-addr 10.9.0.2/24 --mtu "$MTU" --server "10.0.0.1:$PORT" --no-routes \
    --private-key "$logdir/client.key" --peer-key "$SERVER_PUB" \
    >"$logdir/vpn.log" 2>&1 &
vpn_pid=$!

for _ in $(seq 1 40); do
    if ip -n "$CLIENT_NS" link show tun0 >/dev/null 2>&1 &&
       ip -n "$SERVER_NS" link show tun0 >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
ip -n "$CLIENT_NS" link show tun0 >/dev/null 2>&1 || { cat "$logdir/vpn.log"; fail "client tun0 never appeared"; }
ip -n "$SERVER_NS" link show tun0 >/dev/null 2>&1 || { cat "$logdir/vpnd.log"; fail "server tun0 never appeared"; }
echo "both tun0 devices are up"

say "capturing on the underlay while we ping"
ip netns exec "$CLIENT_NS" tcpdump -i vpn-c -n -U --immediate-mode -w "$logdir/underlay.pcap" \
    "udp port $PORT" >"$logdir/tcpdump.txt" 2>&1 &
tcpdump_pid=$!
sleep 1

say "client -> server: ping 10.9.0.1"
if ip netns exec "$CLIENT_NS" ping -c 5 -i 0.3 -W 2 -p cafebabe 10.9.0.1; then
    forward_ok=1
else
    forward_ok=0
fi

say "server -> client: ping 10.9.0.2 (works only once the endpoint is learned)"
if ip netns exec "$SERVER_NS" ping -c 3 -i 0.3 -W 2 -p cafebabe 10.9.0.2; then
    reverse_ok=1
else
    reverse_ok=0
fi

say "MTU check: $((MTU - 28))-byte payload, do-not-fragment"
if ip netns exec "$CLIENT_NS" ping -c 2 -W 2 -M do -s "$((MTU - 28))" 10.9.0.1 >/dev/null; then
    mtu_ok=1
else
    mtu_ok=0
fi
echo "large packets: $([ $mtu_ok -eq 1 ] && echo ok || echo FAILED)"

sleep 0.5
kill -INT "$tcpdump_pid" 2>/dev/null
wait "$tcpdump_pid" 2>/dev/null
grep -E "packets (captured|received|dropped)" "$logdir/tcpdump.txt" | sed "s/^/   /"

say "what the underlay actually carried"
tcpdump -r "$logdir/underlay.pcap" -n -c 4 2>/dev/null
echo
# The payload is a transport-data message: a 16-byte header at udp[8], then
# the sealed inner packet, then its 16-byte Poly1305 tag.
echo "first datagram — 16-byte header, then ciphertext:"
tcpdump -r "$logdir/underlay.pcap" -n -c 1 -X 2>/dev/null | head -12
udp_count=$(tcpdump -r "$logdir/underlay.pcap" -n 2>/dev/null | wc -l)
initiations=$(tcpdump -r "$logdir/underlay.pcap" -n "udp[8] = 1" 2>/dev/null | wc -l)
responses=$(tcpdump -r "$logdir/underlay.pcap" -n "udp[8] = 2" 2>/dev/null | wc -l)
transport=$(tcpdump -r "$logdir/underlay.pcap" -n "udp[8] = 4" 2>/dev/null | wc -l)
bad_reserved=$(tcpdump -r "$logdir/underlay.pcap" -n \
    "udp[9] != 0 or udp[10] != 0 or udp[11] != 0" 2>/dev/null | wc -l)
echo
echo "$udp_count datagrams: $initiations initiation, $responses response, $transport transport"
echo "$bad_reserved with a nonzero reserved field (want 0)"

# The ping payload is the repeating pattern cafebabe. If any of it appears in
# the bytes on the wire, the tunnel is not encrypting.
plaintext_hits=$(python3 -c "
import sys
print(open(sys.argv[1], 'rb').read().count(bytes.fromhex('cafebabecafebabe')))
" "$logdir/underlay.pcap")
echo "occurrences of the ping payload in the captured bytes: $plaintext_hits (want 0)"

say "shutting down on SIGINT"
kill -INT "$vpnd_pid" "$vpn_pid" 2>/dev/null
wait "$vpnd_pid"; vpnd_rc=$?
wait "$vpn_pid";  vpn_rc=$?

echo "--- vpnd (rc=$vpnd_rc) ---"; cat "$logdir/vpnd.log"
echo "--- vpn  (rc=$vpn_rc) ---";  cat "$logdir/vpn.log"

san_hits=$(grep -lE "AddressSanitizer|runtime error|LeakSanitizer" "$logdir"/*.log 2>/dev/null)

say "result"
status=0
[ "$forward_ok" -eq 1 ] || { echo "client -> server ping FAILED"; status=1; }
[ "$reverse_ok" -eq 1 ] || { echo "server -> client ping FAILED"; status=1; }
[ "$mtu_ok"     -eq 1 ] || { echo "large ping FAILED"; status=1; }
[ "$udp_count" -ge 16 ] || { echo "only $udp_count datagrams captured"; status=1; }
[ "$transport" -ge 16 ] || { echo "only $transport transport packets; 8 pings each way should give 20"; status=1; }
[ "$initiations" -ge 1 ] || { echo "no handshake initiation on the wire"; status=1; }
[ "$responses" -ge 1 ]  || { echo "no handshake response on the wire"; status=1; }
[ "$bad_reserved" -eq 0 ] || { echo "$bad_reserved datagrams had a nonzero reserved field"; status=1; }
[ "$plaintext_hits" -eq 0 ] || { echo "the ping payload appears $plaintext_hits times in the clear"; status=1; }
[ "$vpnd_rc" -eq 0 ]    || { echo "vpnd exited $vpnd_rc, expected 0"; status=1; }
[ "$vpn_rc"  -eq 0 ]    || { echo "vpn exited $vpn_rc, expected 0"; status=1; }
[ -z "$san_hits" ]      || { echo "sanitizer output in: $san_hits"; status=1; }

if [ "$status" -eq 0 ]; then
    printf '\033[32mPHASE 1 PASS\033[0m — packets flow both ways, encrypted, clean under ASan/UBSan\n'
else
    printf '\033[31mPHASE 1 FAIL\033[0m — see above; logs in %s\n' "$logdir"
fi

if [ "$keep" -eq 1 ]; then
    echo
    echo "namespaces kept. poke at them with:"
    echo "  sudo ip netns exec $CLIENT_NS bash"
    echo "  sudo $0 --clean    # when you are done"
fi

exit "$status"

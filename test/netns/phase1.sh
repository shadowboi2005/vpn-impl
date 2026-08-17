#!/bin/bash
# Phase 1 acceptance test: a bare, unencrypted tunnel between two network
# namespaces.
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
MTU=1380

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_dir=${VPN_BUILD_DIR:-$repo_root/build/debug}
vpnd=$build_dir/vpnd
vpn=$build_dir/vpn
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
[ -x "$vpn" ]  || fail "$vpn not found — run: cmake --preset debug && cmake --build build/debug"

mkdir -p "$logdir"
rm -f "$logdir"/*.log "$logdir"/*.pcap

# Any leftovers from an interrupted run.
teardown

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
    >"$logdir/vpnd.log" 2>&1 &
vpnd_pid=$!

ip netns exec "$CLIENT_NS" "$vpn" \
    --dev tun0 --tun-addr 10.9.0.2/24 --mtu "$MTU" --server "10.0.0.1:$PORT" --no-routes \
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
ip netns exec "$CLIENT_NS" tcpdump -i vpn-c -n -w "$logdir/underlay.pcap" \
    "udp port $PORT" >/dev/null 2>&1 &
tcpdump_pid=$!
sleep 1

say "client -> server: ping 10.9.0.1"
if ip netns exec "$CLIENT_NS" ping -c 5 -i 0.3 -W 2 10.9.0.1; then
    forward_ok=1
else
    forward_ok=0
fi

say "server -> client: ping 10.9.0.2 (works only once the endpoint is learned)"
if ip netns exec "$SERVER_NS" ping -c 3 -i 0.3 -W 2 10.9.0.2; then
    reverse_ok=1
else
    reverse_ok=0
fi

say "MTU check: 1352-byte payload, do-not-fragment"
if ip netns exec "$CLIENT_NS" ping -c 2 -W 2 -M do -s 1352 10.9.0.1 >/dev/null; then
    mtu_ok=1
else
    mtu_ok=0
fi
echo "large packets: $([ $mtu_ok -eq 1 ] && echo ok || echo FAILED)"

sleep 0.5
kill "$tcpdump_pid" 2>/dev/null
wait "$tcpdump_pid" 2>/dev/null

say "what the underlay actually carried"
tcpdump -r "$logdir/underlay.pcap" -n -c 4 2>/dev/null
echo
echo "first datagram, decoded as the raw IP packet it is:"
tcpdump -r "$logdir/underlay.pcap" -n -c 1 -X 2>/dev/null | head -12
udp_count=$(tcpdump -r "$logdir/underlay.pcap" -n 2>/dev/null | wc -l)
echo
echo "$udp_count UDP datagrams captured on the underlay"

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
[ "$mtu_ok"     -eq 1 ] || { echo "1352-byte ping FAILED"; status=1; }
[ "$udp_count" -gt 0 ]  || { echo "no UDP seen on the underlay"; status=1; }
[ "$vpnd_rc" -eq 0 ]    || { echo "vpnd exited $vpnd_rc, expected 0"; status=1; }
[ "$vpn_rc"  -eq 0 ]    || { echo "vpn exited $vpn_rc, expected 0"; status=1; }
[ -z "$san_hits" ]      || { echo "sanitizer output in: $san_hits"; status=1; }

if [ "$status" -eq 0 ]; then
    printf '\033[32mPHASE 1 PASS\033[0m — packets flow both ways, clean under ASan/UBSan\n'
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

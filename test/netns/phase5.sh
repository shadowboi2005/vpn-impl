#!/bin/bash
# Phase 5 acceptance test: the tunnel actually protects traffic.
#
#   client ns  10.0.0.2/24 ──veth── 10.0.0.1/24  server ns
#     tun0 10.9.0.2/24                 tun0 10.9.0.1/24
#
# Three things get proved here, each against a packet captured off the real
# wire rather than one this script invented:
#
#   1. Nothing readable crosses the wire. The pings carry a known payload
#      pattern; it must appear nowhere in the captured bytes.
#   2. A captured packet, replayed unmodified, is silently dropped — and the
#      server's replay counter, not its auth counter, is the one that moves.
#   3. The same packet with a single bit flipped is silently dropped, and the
#      auth counter is the one that moves.
#
# And after all of it the tunnel still works, which is the part that catches an
# implementation that "drops" a replay by tearing the session down.
#
# Needs root. Everything lives in namespaces that are deleted on exit.
#
#   sudo test/netns/phase5.sh          run the test and clean up
#   sudo test/netns/phase5.sh --keep   leave the namespaces up afterwards
#   sudo test/netns/phase5.sh --clean  just tear down a previous --keep run

set -uo pipefail

CLIENT_NS=vpn-client
SERVER_NS=vpn-server
PORT=51820
MTU=1420
SERVER_UNDERLAY=10.0.0.1

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
build_dir=${VPN_BUILD_DIR:-$repo_root/build/debug}
vpnd=$build_dir/vpnd
vpn=$build_dir/vpn
vpnkey=$build_dir/vpnkey
logdir=${VPN_LOG_DIR:-$repo_root/build/phase5-logs}

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
note() { printf '   %s\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

teardown() {
    ip netns pids "$CLIENT_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns pids "$SERVER_NS" 2>/dev/null | xargs -r kill -9 2>/dev/null
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

for binary in "$vpnd" "$vpn" "$vpnkey"; do
    [ -x "$binary" ] || fail "$binary not found — run: cmake --build build/debug"
done
command -v python3 >/dev/null || fail "python3 is needed for the packet injector"

mkdir -p "$logdir"
rm -f "$logdir"/*.log "$logdir"/*.txt "$logdir"/*.pcap "$logdir"/*.bin
teardown

# ------------------------------------------------------------------ the tools

# Pulls the last client->server transport-data datagram out of a capture, and
# can replay it verbatim or with one bit flipped. Working from a real capture
# rather than a hand-built packet is the point: a forged packet this script
# constructed would only prove that this script cannot forge one.
cat >"$logdir/inject.py" <<'PY'
import socket
import struct
import sys

TRANSPORT = 4


def payloads(path, dst_port):
    """Every UDP payload in a pcap sent to dst_port. Ethernet + IPv4 only."""
    with open(path, "rb") as handle:
        data = handle.read()
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        raise SystemExit(f"unexpected pcap magic {magic:#x}")
    offset = 24
    while offset + 16 <= len(data):
        incl = struct.unpack("<I", data[offset + 8:offset + 12])[0]
        frame = data[offset + 16:offset + 16 + incl]
        offset += 16 + incl
        if len(frame) < 14 + 20 + 8 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17:  # UDP
            continue
        udp = ip[ihl:]
        if struct.unpack("!H", udp[2:4])[0] != dst_port:
            continue
        length = struct.unpack("!H", udp[4:6])[0]
        yield udp[8:length]


def main():
    command = sys.argv[1]
    if command == "extract":
        pcap, out, port = sys.argv[2], sys.argv[3], int(sys.argv[4])
        found = [p for p in payloads(pcap, port) if p and p[0] == TRANSPORT]
        if not found:
            raise SystemExit("no transport-data datagram in the capture")
        with open(out, "wb") as handle:
            handle.write(found[-1])
        print(f"extracted a {len(found[-1])}-byte transport datagram "
              f"(of {len(found)} in the capture)")
    elif command == "send":
        blob, host, port = sys.argv[2], sys.argv[3], int(sys.argv[4])
        with open(blob, "rb") as handle:
            packet = bytearray(handle.read())
        args = sys.argv[5:]
        while args:
            option = args.pop(0)
            if option == "--flip":
                index = int(args.pop(0))
                packet[index] ^= 0x01
                print(f"flipped bit 0 of byte {index}")
            elif option == "--counter":
                # Bytes 8..15, little-endian. A counter the receiver has not
                # seen is what gets a packet past the replay check and in front
                # of the AEAD, which is the only way to test the tag.
                value = int(args.pop(0))
                packet[8:16] = struct.pack("<Q", value)
                print(f"set the counter to {value}")
            else:
                raise SystemExit(f"unknown option {option}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(bytes(packet), (host, port))
        sock.close()
        print(f"sent {len(packet)} bytes to {host}:{port}")
    else:
        raise SystemExit(f"unknown command {command}")


main()
PY

# ------------------------------------------------------------------- topology

say "keys and namespaces"
"$vpnkey" genkey > "$logdir/client.key" && chmod 600 "$logdir/client.key"
"$vpnkey" genkey > "$logdir/server.key" && chmod 600 "$logdir/server.key"
CLIENT_PUB=$("$vpnkey" pubkey < "$logdir/client.key")
SERVER_PUB=$("$vpnkey" pubkey < "$logdir/server.key")
[ -n "$CLIENT_PUB" ] && [ -n "$SERVER_PUB" ] || fail "key generation failed"
note "client public key: $CLIENT_PUB"
note "server public key: $SERVER_PUB"

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

export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1
export UBSAN_OPTIONS=print_stacktrace=1

say "starting the tunnel"
ip netns exec "$SERVER_NS" "$vpnd" \
    --dev tun0 --tun-addr 10.9.0.1/24 --mtu "$MTU" --listen-port "$PORT" --no-nat \
    --private-key "$logdir/server.key" --peer-key "$CLIENT_PUB" \
    >"$logdir/vpnd.log" 2>&1 &
vpnd_pid=$!

ip netns exec "$CLIENT_NS" "$vpn" \
    --dev tun0 --tun-addr 10.9.0.2/24 --mtu "$MTU" --server "$SERVER_UNDERLAY:$PORT" --no-routes \
    --private-key "$logdir/client.key" --peer-key "$SERVER_PUB" \
    >"$logdir/vpn.log" 2>&1 &
vpn_pid=$!

for _ in $(seq 1 60); do
    ip -n "$CLIENT_NS" link show tun0 >/dev/null 2>&1 &&
        ip -n "$SERVER_NS" link show tun0 >/dev/null 2>&1 && break
    sleep 0.1
done
ip -n "$CLIENT_NS" link show tun0 >/dev/null 2>&1 || { cat "$logdir/vpn.log"; fail "client tun0 never appeared"; }

say "bringing the session up (the handshake is on demand, so this takes a ping)"
session_ok=0
for _ in $(seq 1 20); do
    ip netns exec "$CLIENT_NS" ping -c 1 -W 1 10.9.0.1 >/dev/null 2>&1
    if grep -q "session established" "$logdir/vpnd.log" 2>/dev/null; then
        session_ok=1
        break
    fi
    sleep 0.3
done
[ "$session_ok" -eq 1 ] || { cat "$logdir/vpn.log" "$logdir/vpnd.log"; fail "no session was established"; }
note "$(grep 'session established' "$logdir/vpnd.log" | head -1)"

# ------------------------------------------------------------------- capture

say "capturing while the client pings with a known payload"
ip netns exec "$CLIENT_NS" tcpdump -i vpn-c -n -U --immediate-mode \
    -w "$logdir/underlay.pcap" "udp port $PORT" >"$logdir/tcpdump.txt" 2>&1 &
tcpdump_pid=$!
for _ in $(seq 1 60); do
    grep -q "listening on" "$logdir/tcpdump.txt" 2>/dev/null && break
    sleep 0.1
done

if ip netns exec "$CLIENT_NS" ping -c 5 -i 0.3 -W 2 -p cafebabe 10.9.0.1 >/dev/null; then
    ping_before=1
else
    ping_before=0
fi
note "pings before the attacks: $([ $ping_before -eq 1 ] && echo ok || echo FAILED)"

sleep 0.5
kill -INT "$tcpdump_pid" 2>/dev/null
wait "$tcpdump_pid" 2>/dev/null
note "$(grep -E 'packets (captured|received)' "$logdir/tcpdump.txt" | tr '\n' ' ')"

say "1. is anything readable on the wire?"
plaintext_hits=$(python3 -c "
import sys
print(open(sys.argv[1], 'rb').read().count(bytes.fromhex('cafebabecafebabe')))
" "$logdir/underlay.pcap")
note "occurrences of the ping payload in the captured bytes: $plaintext_hits (want 0)"
echo "   first captured datagram:"
tcpdump -r "$logdir/underlay.pcap" -n -c 1 -X 2>/dev/null | head -7 | sed 's/^/   /'

# ------------------------------------------------------------------- attacks

say "extracting a real transport packet to attack"
python3 "$logdir/inject.py" extract "$logdir/underlay.pcap" "$logdir/packet.bin" "$PORT" \
    | sed 's/^/   /' || fail "could not extract a transport datagram"

read_counter() {  # read_counter <name>  — from the server's live stats
    grep -oE "[0-9]+ $1" "$logdir/vpnd-stats.txt" 2>/dev/null | head -1 | cut -d' ' -f1
}

say "2. replaying a captured packet, unmodified"
for _ in 1 2 3; do
    ip netns exec "$CLIENT_NS" python3 "$logdir/inject.py" send \
        "$logdir/packet.bin" "$SERVER_UNDERLAY" "$PORT" | sed 's/^/   /'
done
sleep 0.3

say "3. the same packet with one bit flipped, counter untouched"
# Byte 20 is inside the ciphertext. The counter is unchanged, so this is still a
# counter the server has already delivered — and the replay check runs *before*
# the AEAD, on purpose, so that a replay flood costs no decryptions. It is
# caught as a replay, not as a forgery, and that is the right answer.
ip netns exec "$CLIENT_NS" python3 "$logdir/inject.py" send \
    "$logdir/packet.bin" "$SERVER_UNDERLAY" "$PORT" --flip 20 | sed 's/^/   /'
sleep 0.2

say "4. a forgery: bit flipped, and a counter the server has never seen"
# A fresh counter gets past the replay window, which is the only way to put a
# packet in front of the AEAD. Nothing but the real key can produce a tag that
# verifies, so this must fail there.
ip netns exec "$CLIENT_NS" python3 "$logdir/inject.py" send \
    "$logdir/packet.bin" "$SERVER_UNDERLAY" "$PORT" --flip 20 --counter 1000000 \
    | sed 's/^/   /'
# And a counter far beyond anything real. If a forgery could advance the window,
# the genuine packets that follow would be rejected as ancient — which is what
# the pings after this are checking.
ip netns exec "$CLIENT_NS" python3 "$logdir/inject.py" send \
    "$logdir/packet.bin" "$SERVER_UNDERLAY" "$PORT" --counter 4000000000 \
    | sed 's/^/   /'
sleep 0.3

say "5. does the tunnel still work?"
if ip netns exec "$CLIENT_NS" ping -c 3 -i 0.3 -W 2 10.9.0.1 >/dev/null; then
    ping_after=1
else
    ping_after=0
fi
note "pings after the attacks: $([ $ping_after -eq 1 ] && echo ok || echo FAILED)"

if ip netns exec "$SERVER_NS" ping -c 2 -i 0.3 -W 2 10.9.0.2 >/dev/null; then
    reverse_ok=1
else
    reverse_ok=0
fi
note "server -> client still works: $([ $reverse_ok -eq 1 ] && echo ok || echo FAILED)"

# ------------------------------------------------------------------- verdict

say "shutting down and reading the server's counters"
kill -INT "$vpnd_pid" "$vpn_pid" 2>/dev/null
wait "$vpnd_pid"; vpnd_rc=$?
wait "$vpn_pid";  vpn_rc=$?

echo "--- vpnd (rc=$vpnd_rc) ---"; sed 's/^/   /' "$logdir/vpnd.log"
echo "--- vpn  (rc=$vpn_rc) ---";  sed 's/^/   /' "$logdir/vpn.log"

counter() {  # counter <label>  — pulls "<n> <label>" out of the server's stats
    grep -oE "[0-9]+ $1" "$logdir/vpnd.log" | tail -1 | cut -d' ' -f1
}
replayed=$(counter replayed)
failed_auth=$(counter failed-auth)
replayed=${replayed:-0}
failed_auth=${failed_auth:-0}
note "server counted $replayed replayed and $failed_auth failed-auth packets"

san_hits=$(grep -lE "AddressSanitizer|runtime error|LeakSanitizer" "$logdir"/*.log 2>/dev/null)

say "result"
status=0
[ "$ping_before" -eq 1 ]   || { echo "traffic did not flow before the attacks"; status=1; }
[ "$plaintext_hits" -eq 0 ] || { echo "the ping payload appears $plaintext_hits times in the clear"; status=1; }
# Three verbatim replays, plus the bit-flipped one whose counter was stale.
[ "$replayed" -eq 4 ]      || { echo "expected 4 replayed packets to be counted, got $replayed"; status=1; }
# The two forgeries carrying counters the server had never seen.
[ "$failed_auth" -eq 2 ]   || { echo "expected 2 forgeries to fail authentication, got $failed_auth"; status=1; }
[ "$ping_after" -eq 1 ]    || { echo "the tunnel stopped working after the attacks"; status=1; }
[ "$reverse_ok" -eq 1 ]    || { echo "server -> client stopped working"; status=1; }
[ "$vpnd_rc" -eq 0 ]       || { echo "vpnd exited $vpnd_rc, expected 0"; status=1; }
[ "$vpn_rc" -eq 0 ]        || { echo "vpn exited $vpn_rc, expected 0"; status=1; }
[ -z "$san_hits" ]         || { echo "sanitizer output in: $san_hits"; status=1; }

if [ "$status" -eq 0 ]; then
    printf '\033[32mPHASE 5 PASS\033[0m — nothing readable on the wire, replays and forgeries dropped, tunnel survives\n'
else
    printf '\033[31mPHASE 5 FAIL\033[0m — see above; logs in %s\n' "$logdir"
fi

if [ "$keep" -eq 1 ]; then
    echo
    echo "namespaces kept. poke at them with:"
    echo "  sudo ip netns exec $CLIENT_NS bash"
    echo "  sudo $0 --clean    # when you are done"
fi

exit "$status"

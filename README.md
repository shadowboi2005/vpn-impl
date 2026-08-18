# vpn-impl

A minimal but secure IPv4 VPN in C++20, built from scratch and modelled
on WireGuard — same wire format, same Noise IK handshake, same constants, and
keys interchangeable with `wg`.


---

## Getting the source

The BLAKE2s hash comes from the BLAKE2 authors' own library, as a submodule.
libsodium ships BLAKE2**b**, which is a different algorithm, so this is not
optional.

```sh
git clone --recursive <repo>
# or, in an existing clone:
git submodule update --init --recursive
```

The build stops with a clear error if the submodule is missing, so it cannot
silently build against a hash that is not there.

## Dependencies

```sh
sudo apt install cmake clang libsodium-dev
```

Everything else : `ip`, `iptables`, `tcpdump`, `python3`, `curl` — is used only
by the test harnesses.

## Building

```sh
cmake --preset debug && cmake --build build/debug
```

Three presets:

| preset | what it is for |
|---|---|
| `debug` | ASan + UBSan, `-Werror`. The default. Run everything here. |
| `release` | optimised, no sanitizers. Use for throughput measurement only. |
| `fuzz` | libFuzzer + ASan + UBSan. Clang only. |

The sanitizers are not optional extras — the parser handles attacker-controlled
bytes, and a sanitizer added late finds bugs you have already built on.

## Running the tests

```sh
# unit tests — no privileges needed
cmake --build build/debug && ctest --test-dir build/debug --output-on-failure

# the fuzzers
cmake --preset fuzz && cmake --build build/fuzz
build/fuzz/decode_fuzz    -max_total_time=300 test/fuzz/corpus
build/fuzz/handshake_fuzz -max_total_time=300 test/fuzz/handshake_corpus
build/fuzz/session_fuzz   -max_total_time=300 test/fuzz/session_corpus
```

The end-to-end tests build network namespaces, so they need root. They do not
touch this machine's networking: every interface, route, firewall rule and
sysctl lives inside a namespace that is deleted on exit.

```sh
sudo test/netns/phase1.sh   # traffic both ways, framing, nothing readable on the wire
sudo test/netns/phase2.sh   # full-tunnel routing, NAT, IPv6 policy, teardown
sudo test/netns/phase5.sh   # replay and forgery, against a packet captured off the wire
```

Add `--keep` to leave the namespaces up and poke at them, then `--clean` to
remove them.

## Keys

Key format and generation match `wg`, so keys are interchangeable with a real
WireGuard configuration.

```sh
build/debug/vpnkey genkey > private.key
build/debug/vpnkey pubkey < private.key > public.key
```

`genkey` refuses to write to a terminal — a private key in scrollback is a
private key you have to rotate.

## Running it for real

Both binaries need `CAP_NET_ADMIN`, so root for now 

Server:

```sh
sudo build/debug/vpnd \
    --dev tun0 --tun-addr 10.9.0.1/24 --listen-port 51820 \
    --private-key server.key --peer-key "$(cat client.pub)" \
    --wan-if eth0
```

Client:

```sh
sudo build/debug/vpn \
    --dev tun0 --tun-addr 10.9.0.2/24 --server <server-ip>:51820 \
    --private-key client.key --peer-key "$(cat server.pub)"
```

Each side needs its own private key and the other's public key. There is no
unencrypted mode: without keys, neither binary starts.

Both print what they installed and what they tore down, and both exit cleanly on
`SIGINT` with counters and a full teardown.

The handshake happens **on demand**: the client initiates when it has a packet to
send and no session, the way WireGuard does. The consequence is that the first
packet of an idle tunnel is dropped rather than queued, so the first `ping` of a
session shows one lost packet. Keepalives, which arrive in Phase 6, largely hide
this.

### Flags worth knowing

| flag | |
|---|---|
| `--mtu N` | tunnel MTU, default 1420 (WireGuard's) |
| `--no-routes` (client) | leave the routing table alone |
| `--no-nat` (server) | do not forward or masquerade |
| `--wan-if NAME` (server) | interface to masquerade out of; autodetected otherwise |
| `--host-ipv6 MODE` (client) | `refuse` (default), `block`, or `ignore` |
| `--private-key PATH` | our private key, base64, one line — required |
| `--peer-key BASE64` | the other side's public key — required |

**`--host-ipv6` defaults to `refuse` on purpose.** The tunnel carries IPv4 only,
so a host that can route IPv6 has a complete way around it — every name with a
AAAA record gets reached outside the tunnel, in the clear, from the real address.
`block` firewalls IPv6 off for the life of the tunnel; `ignore` accepts the leak
and says so.

### What it does to your machine, and what undoes it

The client installs a host route to the server, then `0.0.0.0/1` and
`128.0.0.0/1` over the tunnel. The server sets `ip_forward`, a MASQUERADE rule
and two FORWARD rules. Every one of those is held by an object whose destructor
reverses it, so `SIGINT`, an exception, or a failed startup all unwind the same
way.

`SIGKILL` does not, and cannot — destructors do not run. What survives is the
host route to the server, the server's firewall rules, and `ip_forward`. The
tunnel's own default routes disappear on their own, because the kernel drops
routes when the interface does. `test/netns/phase2.sh` measures and prints this
rather than pretending otherwise.

## Layout

```
src/
  vpnd.cpp vpn.cpp   server and client entrypoints
  vpnkey.cpp         key generation, wg-compatible
  tun.{h,cpp}        TUN device
  udp.{h,cpp}        UDP socket
  netcfg.{h,cpp}     routes, NAT, sysctls — and the RAII guards that undo them
  wire.{h,cpp}       WireGuard message framing, encode/decode
  crypto.{h,cpp}     BLAKE2s, HMAC, KDF, X25519, ChaCha20-Poly1305
  noise.{h,cpp}      Noise_IKpsk2 handshake state machine
  session.{h,cpp}    transport keys, send counter, replay window
  secure_buf.h       zeroizing key storage
  relay.{h,cpp}      the epoll loop
  fd.h args.h        small shared pieces
test/
  unit/              framing, crypto vectors, handshake, replay window
  fuzz/              libFuzzer harnesses and corpora — framing, handshake, transport
  netns/             end-to-end tests in network namespaces
third-party/
  libb2/             BLAKE2 authors' library (submodule) — BLAKE2s only
  libb2-config/      a minimal config.h so the reference file builds standalone
```

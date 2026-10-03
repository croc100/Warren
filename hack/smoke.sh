#!/usr/bin/env bash
# End-to-end smoke test: drives the real binaries through the whole flow and
# finishes by running the L1 gate.
#
# The unit tests already cover the protocol; what they cannot cover is the wiring
# — flag parsing, key handling, the bridge-file round trip, the relay refusing an
# unusable cover site — and a regression there is invisible until someone tries to
# run the thing. So this exists, and CI runs it.
#
# The stand-in "real site" is a Go TLS server rather than openssl s_server or
# python's ssl module on purpose: Warren refuses to borrow from a site that does
# not negotiate X25519MLKEM768, and whether a distro's OpenSSL supports ML-KEM
# varies. Go's does, and go.mod pins the toolchain, so this behaves the same on
# every machine.
set -euo pipefail

RELAY_PORT="${RELAY_PORT:-18443}"
SITE_PORT="${SITE_PORT:-19443}"
# A second, unrelated site, used only by the gate canary at the end: the gate has
# to reject a relay compared against a site it does not borrow from, or its PASS
# on the real pair means nothing.
OTHER_SITE_PORT="${OTHER_SITE_PORT:-19444}"
SITE_SNI="${SITE_SNI:-www.example.com}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
pids=()

cleanup() {
  for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$tmp"
}
trap cleanup EXIT

step() { printf '\n=== %s\n' "$1"; }
fail() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }
expect() { # expect <needle> <file> <message>
  grep -qF -- "$1" "$2" || { echo "--- output ---"; cat "$2"; fail "$3"; }
}

step "building"
cd "$root"
go build -o "$tmp/node" ./cmd/node
go build -o "$tmp/cli" ./cmd/cli
go build -o "$tmp/bootstrap" ./cmd/bootstrap
go build -o "$tmp/probe" ./cmd/probe

step "starting a real TLS 1.3 site for the relay to borrow"
cat > "$tmp/site.go" <<'SITE'
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: os.Args[2]},
		DNSNames:     []string{os.Args[2]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:"+os.Args[1], &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("site: listening")

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			c.Read(make([]byte, 1024))
			body := "the real site speaking"
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body))
		}(conn)
	}
}
SITE
# Built rather than `go run`: go run spawns the compiled binary as a child, so
# killing go run's pid on cleanup leaves the listener holding the port and the
# next run fails to bind.
go build -o "$tmp/site" "$tmp/site.go"
"$tmp/site" "$SITE_PORT" "$SITE_SNI" > "$tmp/site.log" 2>&1 &
pids+=($!)
disown

for _ in $(seq 1 40); do
  if grep -q "site: listening" "$tmp/site.log" 2>/dev/null; then break; fi
  sleep 0.5
done
grep -q "site: listening" "$tmp/site.log" || { cat "$tmp/site.log"; fail "the stand-in site never came up"; }

# The canary's site. Same code, its own process, so it mints its own
# certificate — which is what makes it something the gate must not confuse with
# the site the relay actually borrows.
"$tmp/site" "$OTHER_SITE_PORT" "$SITE_SNI" > "$tmp/other-site.log" 2>&1 &
pids+=($!)
disown
for _ in $(seq 1 40); do
  if grep -q "site: listening" "$tmp/other-site.log" 2>/dev/null; then break; fi
  sleep 0.5
done
grep -q "site: listening" "$tmp/other-site.log" || { cat "$tmp/other-site.log"; fail "the canary's second site never came up"; }

step "measuring the site (an operator's cover-selection check)"
"$tmp/node" -profile-only -profile-insecure \
  -fallback-addr="127.0.0.1:$SITE_PORT" -fallback-sni="$SITE_SNI" > "$tmp/profile.log" 2>&1 \
  || { cat "$tmp/profile.log"; fail "profiling the site failed"; }
cat "$tmp/profile.log"
# 0x11ec is X25519MLKEM768. A relay refuses to borrow from a site that negotiates
# anything else, because its real ServerHello would be hundreds of bytes smaller
# than Warren's.
expect "group 0x11ec" "$tmp/profile.log" "the site did not negotiate a hybrid post-quantum group, so the relay would refuse it"
expect "client Finished" "$tmp/profile.log" "the profile is missing the measured client Finished size"

step "generating keys"
eval "$("$tmp/node" -genkey 2>/dev/null)"        # WARREN_RELAY_KEY_HEX + ..._PUBKEY_HEX
eval "$("$tmp/bootstrap" -genkey 2>/dev/null)"  # WARREN_BRIDGE_KEY_HEX + ..._ANCHOR_HEX
[ ${#WARREN_RELAY_KEY_HEX} -eq 64 ] || fail "relay private key is not 64 hex chars"
[ ${#WARREN_RELAY_PUBKEY_HEX} -eq 64 ] || fail "relay public key is not 64 hex chars"
[ -n "${WARREN_BRIDGE_ANCHOR_HEX:-}" ] || fail "bootstrap -genkey did not emit a trust anchor"
relay_pub="$WARREN_RELAY_PUBKEY_HEX"

step "signing and verifying a bridge descriptor"
"$tmp/bootstrap" -sign -ttl=1h \
  -bridge="127.0.0.1:$RELAY_PORT|$SITE_SNI|$relay_pub" > "$tmp/bridges.txt" 2>/dev/null
"$tmp/bootstrap" -verify -file="$tmp/bridges.txt" > "$tmp/verify.log" 2>&1 \
  || { cat "$tmp/verify.log"; fail "a freshly signed descriptor did not verify"; }
expect "OK" "$tmp/verify.log" "descriptor verification did not report OK"
expect "fresh" "$tmp/verify.log" "a descriptor signed seconds ago was not reported fresh"

step "starting the relay"
"$tmp/node" -listen="127.0.0.1:$RELAY_PORT" -profile-insecure \
  -fallback-addr="127.0.0.1:$SITE_PORT" -fallback-sni="$SITE_SNI" > "$tmp/node.log" 2>&1 &
pids+=($!)
disown
for _ in $(seq 1 40); do
  if grep -q "listening on" "$tmp/node.log" 2>/dev/null; then break; fi
  sleep 0.5
done
grep -q "listening on" "$tmp/node.log" || { cat "$tmp/node.log"; fail "the relay never came up"; }

step "a genuine client, via the signed descriptor"
"$tmp/cli" -bridge-file="$tmp/bridges.txt" -message="hello from behind the firewall" > "$tmp/cli.log" 2>&1 \
  || { cat "$tmp/cli.log"; fail "a genuine client could not reach the relay"; }
expect "hello from behind the firewall" "$tmp/cli.log" "the relay did not echo the client's message"

step "a client fed a tampered descriptor"
sed "s/|$relay_pub/|$(printf 'cc%.0s' $(seq 32))/" "$tmp/bridges.txt" > "$tmp/tampered.txt"
if "$tmp/cli" -bridge-file="$tmp/tampered.txt" -message=nope > "$tmp/tampered.log" 2>&1; then
  cat "$tmp/tampered.log"
  fail "a descriptor whose relay key was swapped was accepted"
fi
echo "rejected, as it must be: $(tail -1 "$tmp/tampered.log")"

step "an ordinary HTTPS client, which is what a censor's prober is"
# It holds no tag, so the relay splices it to the real site: it gets that site's
# certificate and that site's body, because that is literally what answered. (The
# gate below checks the two endpoints agree on the harder cases — plaintext HTTP,
# record-shaped junk, a replayed hello — where "no reply" is the correct reply.)
if command -v curl > /dev/null; then
  probe_body="$(curl -sk --max-time 10 "https://127.0.0.1:$RELAY_PORT/" || true)"
  case "$probe_body" in
    *"the real site speaking"*) echo "got the borrowed site's own response through the relay" ;;
    *) fail "an HTTPS client through the relay did not get the real site's body (got: ${probe_body:0:60})" ;;
  esac
else
  echo "curl not available, skipping"
fi

step "the L1 gate"
"$tmp/probe" -relay="127.0.0.1:$RELAY_PORT" -site="127.0.0.1:$SITE_PORT" \
  -sni="$SITE_SNI" -relay-key="$relay_pub" > "$tmp/gate.log" 2>&1 || {
  cat "$tmp/gate.log"
  fail "the gate found something that separates the relay from the site it borrows"
}
sed -n '/^probe /,$p' "$tmp/gate.log"
expect "PASS" "$tmp/gate.log" "the gate did not report PASS"

step "the gate's own failure path (canary)"
# A gate that has quietly stopped working reports PASS, forever, and nothing
# above would notice. So it is pointed at a pair it must reject: the same relay,
# compared against a site it does not borrow from. Different certificate,
# different everything — if this comes back PASS, or exits zero, then the
# verdict printed above is not evidence of anything.
#
# The unit-test canaries (internal/network/probe/canary_test.go) cover the
# individual measurements; this one covers the binary, which is the part CI and
# a release actually gate on: the comparison running, the distinguishers being
# counted, and os.Exit reflecting the count.
if "$tmp/probe" -relay="127.0.0.1:$RELAY_PORT" -site="127.0.0.1:$OTHER_SITE_PORT" \
  -sni="$SITE_SNI" -relay-key="$relay_pub" > "$tmp/canary.log" 2>&1; then
  cat "$tmp/canary.log"
  fail "the gate passed a relay compared against a site it does not borrow from; it is not measuring anything"
fi
expect "FAIL" "$tmp/canary.log" "the gate exited non-zero but did not report FAIL"
echo "rejected, as it must be: $(grep -m1 '^FAIL' "$tmp/canary.log")"

printf '\nsmoke: everything passed\n'

.PHONY: test build smoke gate fmt vet clean

# Everything that gates a change.
test:
	go test ./... -race

fmt:
	gofmt -l ./cmd ./internal

vet:
	go vet ./...

build:
	go build -o bin/node ./cmd/node
	go build -o bin/cli ./cmd/cli
	go build -o bin/bootstrap ./cmd/bootstrap
	go build -o bin/probe ./cmd/probe

# End-to-end: stands up a real TLS site, a relay and a client, then runs the gate.
# This is what CI runs.
smoke:
	./hack/smoke.sh

# The L1 gate on its own: probe a relay against the site it borrows from. Needs a running
# relay and its public key — see the README's "Try it" section.
#   make gate RELAY=127.0.0.1:8443 SITE=127.0.0.1:9443 SNI=www.example.com KEY=<hex>
gate: build
	./bin/probe -relay=$(RELAY) -site=$(SITE) -sni=$(SNI) -relay-key=$(KEY)

clean:
	rm -rf bin

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DIST    := dist
LDFLAGS := -s -w -X main.Version=$(VERSION)

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all test vet check dist clean nowhere nowhere-check

all: check

test:
	go test ./...

vet:
	go vet ./...

check: test vet
	go run ./cmd/nowhere-check

nowhere-check:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o nowhere-check ./cmd/nowhere-check

nowhere:
	cd cmd/nowhere && GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ../../nowhere .

dist:
	rm -rf "$(DIST)"
	mkdir -p "$(DIST)"
	@for spec in $(PLATFORMS); do \
		os=$${spec%/*}; \
		arch=$${spec#*/}; \
		ext=; \
		if [ "$$os" = windows ]; then ext=.exe; fi; \
		out="$(DIST)/nowhere_$(VERSION)_$${os}_$${arch}$$ext"; \
		echo "building $$out"; \
		cd cmd/nowhere && GOWORK=off CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "../../$$out" .; \
		cd ../..; \
		cout="$(DIST)/nowhere-check_$(VERSION)_$${os}_$${arch}$$ext"; \
		echo "building $$cout"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o "$$cout" ./cmd/nowhere-check; \
	done
	cd "$(DIST)" && sha256sum * > SHA256SUMS
	@echo "artifacts in $(DIST)/"

clean:
	rm -rf "$(DIST)" nowhere nowhere-check

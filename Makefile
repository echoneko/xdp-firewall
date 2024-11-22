.PHONY: generate
## generate: generate the eBPF code
generate:
	@ go generate

.PHONY: build
## build: build the application
build:
	@ go build -o ebpfdrop

.PHONY: run
## run: run the application
run: generate build
	@ if [ -z "$(BLOCKED_IP)" ]; then echo >&2 please set blocked ip via the variable BLOCKED_IP; exit 2; fi
	@ ./ebpfdrop $(BLOCKED_IP) $(INTERFACE)

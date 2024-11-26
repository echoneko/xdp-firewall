.PHONY: generate
## generate: generate the eBPF code
generate:
	@ go generate

.PHONY: build
## build: build the application
build:
	@ go build -o ebpfdrop

.PHONY: run-config
## run: run the application
run-config: generate build
	@ if [ -z "$(CONFIG_FILE)" ]; then echo >&2 "please set CONFIG_FILE"; exit 2; fi
	@ ./ebpfdrop $(CONFIG_FILE) $(INTERFACE)

TOP?=/home/jun/ghq/github.com/harmony-one
export CGO_CFLAGS:=-I$(TOP)/bls/include -I$(TOP)/mcl/include -I/usr/local/opt/openssl/include
export CGO_LDFLAGS:=-L$(TOP)/bls/lib -L/usr/local/opt/openssl/lib
export LD_LIBRARY_PATH:=$(TOP)/bls/lib:$(TOP)/mcl/lib:/usr/local/opt/openssl/lib

.PHONY: test
test:
	@go test -v ./...

.PHONY: proto-gen
proto-gen:
	@echo "Generating Protobuf files"
	docker run -v $(CURDIR):/workspace --workdir /workspace tendermintdev/sdk-proto-gen sh ./scripts/protocgen.sh

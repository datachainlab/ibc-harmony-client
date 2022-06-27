module github.com/datachainlab/ibc-harmony-client

go 1.16

replace (
	github.com/ethereum/go-ethereum => github.com/ethereum/go-ethereum v1.9.9
	github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1
)

require (
	github.com/confio/ics23/go v0.6.6
	github.com/cosmos/cosmos-sdk v0.43.0-beta1
	github.com/cosmos/ibc-go v1.0.0-beta1
	github.com/ethereum/go-ethereum v1.9.25
	github.com/gogo/protobuf v1.3.3
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/grpc-gateway v1.16.0
	github.com/harmony-one/bls v0.0.6
	github.com/harmony-one/harmony v1.10.3-0.20220129011036-4ea9072e5eda
	github.com/spf13/cobra v1.1.3
	google.golang.org/protobuf v1.26.0
)

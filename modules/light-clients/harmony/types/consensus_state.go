package types

import (
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/harmony-one/harmony/shard"
)

func (cs ConsensusState) ClientType() string {
	return HarmonyClient
}

// GetRoot returns the commitment root of the consensus state,
// which is used for key-value pair verification.
func (cs ConsensusState) GetRoot() exported.Root {
	return root{value: cs.Root}
}

// GetTimestamp returns the timestamp (in nanoseconds) of the consensus state
func (cs ConsensusState) GetTimestamp() uint64 {
	return cs.Timestamp
}

func (cs ConsensusState) ValidateBasic() error {
	if len(cs.Root) == 0 {
		return sdkerrors.Wrap(clienttypes.ErrInvalidConsensus, "root cannot be empty")
	}
	if cs.Timestamp == 0 {
		return sdkerrors.Wrap(clienttypes.ErrInvalidConsensus, "timestamp cannot be 0")
	}
	return nil
}

func (es EpochState) GetCommittee() *shard.Committee {
	var committee shard.Committee
	if err := rlp.DecodeBytes(es.Committee, &committee); err != nil {
		panic(err)
	}
	return &committee
}

type root struct {
	value []byte
}

var _ exported.Root = (*root)(nil)

func (r root) GetHash() []byte {
	return r.value
}

func (r root) Empty() bool {
	return len(r.value) == 0
}

package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/modules/core/24-host"
	"github.com/cosmos/ibc-go/modules/core/exported"
)

// SetConsensusState stores the consensus state at the given height.
func SetConsensusState(clientStore sdk.KVStore, cdc codec.BinaryCodec, consensusState *ConsensusState, height exported.Height) {
	key := host.ConsensusStateKey(height)
	val := clienttypes.MustMarshalConsensusState(cdc, consensusState)
	clientStore.Set(key, val)
}

// GetConsensusState retrieves the consensus state from the client prefixed
// store. An error is returned if the consensus state does not exist.
func GetConsensusState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height) (*ConsensusState, error) {
	bz := store.Get(host.ConsensusStateKey(height))
	if bz == nil {
		return nil, sdkerrors.Wrapf(
			clienttypes.ErrConsensusStateNotFound,
			"consensus state does not exist for height %s", height,
		)
	}

	consensusStateI, err := clienttypes.UnmarshalConsensusState(cdc, bz)
	if err != nil {
		return nil, sdkerrors.Wrapf(clienttypes.ErrInvalidConsensus, "unmarshal error: %v", err)
	}

	consensusState, ok := consensusStateI.(*ConsensusState)
	if !ok {
		return nil, sdkerrors.Wrapf(
			clienttypes.ErrInvalidConsensus,
			"invalid consensus type %T, expected %T", consensusState, &ConsensusState{},
		)
	}

	return consensusState, nil
}

// SetEpochState stores the epoch state at the given epoch.
func SetEpochState(clientStore sdk.KVStore, cdc codec.BinaryCodec, epochState *EpochState, epoch uint64) {
	bz, err := cdc.Marshal(epochState)
	if err != nil {
		panic(err)
	}
	clientStore.Set(EpochStateKey(epoch), bz)
}

// GetEpochState retrieves the `epoch` state from the client prefixed
// store. An error is returned if the epoch state does not exist.
func GetEpochState(clientStore sdk.KVStore, cdc codec.BinaryCodec, epoch uint64) (*EpochState, error) {
	bz := clientStore.Get(EpochStateKey(epoch))
	if bz == nil {
		return nil, sdkerrors.Wrapf(
			ErrEpochStateNotFound,
			"epoch state does not exist for height %v", epoch,
		)
	}
	var epochState EpochState
	if err := cdc.Unmarshal(bz, &epochState); err != nil {
		return nil, err
	}
	return &epochState, nil
}

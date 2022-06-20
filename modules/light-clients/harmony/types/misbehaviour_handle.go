package types

import (
	"bytes"
	time "time"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
)

func (cs ClientState) CheckMisbehaviourAndUpdateState(
	ctx sdk.Context,
	cdc codec.BinaryCodec,
	clientStore sdk.KVStore,
	misbehaviour exported.Misbehaviour,
) (exported.ClientState, error) {
	hmyMisbehaviour, ok := misbehaviour.(*Misbehaviour)
	if !ok {
		return nil, sdkerrors.Wrapf(
			clienttypes.ErrInvalidClientType,
			"misbehaviour type %T, expected %T", misbehaviour, &Misbehaviour{})
	}

	if cs.ShardId == 0 {
		if len(hmyMisbehaviour.Header1.ShardHeader) != 0 || len(hmyMisbehaviour.Header2.ShardHeader) != 0 {
			return nil, sdkerrors.Wrap(
				clienttypes.ErrInvalidMisbehaviour, "misbehaviour with a shard header is invalid for beacon")
		}
		if err := cs.CheckBeaconMisbehaviour(ctx, cdc, clientStore, hmyMisbehaviour); err != nil {
			return nil, err
		}
	} else {
		if err := cs.CheckMisbehaviourForShard(ctx, cdc, clientStore, hmyMisbehaviour); err != nil {
			return nil, err
		}
	}
	cs.Frozen = true
	return &cs, nil
}

// Common for beacon and shard
func (cs ClientState) CheckBeaconMisbehaviour(
	ctx sdk.Context,
	cdc codec.BinaryCodec,
	clientStore sdk.KVStore,
	misbehaviour *Misbehaviour,
) error {
	// misbehaviour.ValidateBasic() checks that each misbehaviour header has just one beacon header
	bh1 := misbehaviour.Header1.BeaconHeaders[0]
	bh2 := misbehaviour.Header2.BeaconHeaders[0]
	header1, err := rlpDecodeHeader(bh1.Header)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode beacon header of Header1")
	}
	header2, err := rlpDecodeHeader(bh2.Header)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode beacon header of Header1")
	}
	if bytes.Equal(header1.Hash().Bytes(), header2.Hash().Bytes()) {
		return sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "headers block hashes are equal")
	}

	hmyConsensusState1, err := GetConsensusState(clientStore, cdc, misbehaviour.Header1.GetHeight())
	if err != nil {
		return sdkerrors.Wrapf(err, "could not get consensus state from clientStore for Header1 at Height: %s", misbehaviour.Header1)
	}
	hmyConsensusState2, err := GetConsensusState(clientStore, cdc, misbehaviour.Header2.GetHeight())
	if err != nil {
		return sdkerrors.Wrapf(err, "could not get consensus state from clientStore for Header2 at Height: %s", misbehaviour.Header1)
	}
	currentTimestamp := ctx.BlockTime()
	if err := checkTimestamp(hmyConsensusState1.Timestamp, cs.TrustingPeriod, currentTimestamp); err != nil {
		return err
	}
	if err := checkTimestamp(hmyConsensusState2.Timestamp, cs.TrustingPeriod, currentTimestamp); err != nil {
		return err
	}

	epochState1, err := GetEpochState(clientStore, cdc, header1.Epoch().Uint64())
	if err != nil {
		return sdkerrors.Wrapf(err, "could not get epoch state for Header1 at Epoch: %d", header1.Epoch())
	}
	epochState2, err := GetEpochState(clientStore, cdc, header2.Epoch().Uint64())
	if err != nil {
		return sdkerrors.Wrapf(err, "could not get epoch state for Header2 at Epoch: %d", header1.Epoch())
	}
	// Verify that each is a valid beacon header with sufficient signatures
	if err := VerifyCommitSig(header1, epochState1.GetCommittee(), bh1.CommitSig, bh1.CommitBitmap); err != nil {
		return sdkerrors.Wrap(err, "failed to verify committee signature of Header1")
	}
	if err := VerifyCommitSig(header2, epochState2.GetCommittee(), bh2.CommitSig, bh2.CommitBitmap); err != nil {
		return sdkerrors.Wrap(err, "failed to verify committee signature of Header2")
	}
	return nil
}

func (cs ClientState) CheckMisbehaviourForShard(
	ctx sdk.Context,
	cdc codec.BinaryCodec,
	clientStore sdk.KVStore,
	misbehaviour *Misbehaviour,
) error {
	if misbehaviour.Header1.ShardHeader != nil && misbehaviour.Header2.ShardHeader != nil {
		return cs.CheckShardMisbehaviour(ctx, cdc, clientStore, misbehaviour)
	} else {
		return cs.CheckBeaconMisbehaviour(ctx, cdc, clientStore, misbehaviour)
	}
}

// For a case where two shard headers with the same Block Number are submitted
func (cs ClientState) CheckShardMisbehaviour(
	ctx sdk.Context,
	cdc codec.BinaryCodec,
	clientStore sdk.KVStore,
	misbehaviour *Misbehaviour,
) error {
	shardHeader1, err := rlpDecodeHeader(misbehaviour.Header1.ShardHeader)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode shard header of Header1")
	}
	shardHeader2, err := rlpDecodeHeader(misbehaviour.Header2.ShardHeader)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode shard header of Header2")
	}
	hmyConsensusState1, err := GetConsensusState(clientStore, cdc, misbehaviour.Header1.GetHeight())
	if err != nil {
		return sdkerrors.Wrapf(err, "could not get consensus state from clientStore for Header1 at Height: %s", misbehaviour.Header1)
	}
	hmyConsensusState2, err := GetConsensusState(clientStore, cdc, misbehaviour.Header2.GetHeight())
	if err != nil {
		return sdkerrors.Wrapf(err, "could not get consensus state from clientStore for Header2 at Height: %s", misbehaviour.Header1)
	}

	currentTimestamp := ctx.BlockTime()
	if err := checkTimestamp(hmyConsensusState1.Timestamp, cs.TrustingPeriod, currentTimestamp); err != nil {
		return err
	}
	if err := checkTimestamp(hmyConsensusState2.Timestamp, cs.TrustingPeriod, currentTimestamp); err != nil {
		return err
	}

	bh1 := misbehaviour.Header1.BeaconHeaders[0]
	bh2 := misbehaviour.Header2.BeaconHeaders[0]
	beaconHeader1, err := rlpDecodeHeader(bh1.Header)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode beacon header of Header1")
	}
	beaconHeader2, err := rlpDecodeHeader(bh2.Header)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode beacon header of Header1")
	}

	if err := checkCrossLink(shardHeader1, beaconHeader1, misbehaviour.Header1.CrossLinkIndex); err != nil {
		return sdkerrors.Wrap(err, "could not verify cross link of Header1")
	}
	if err := checkCrossLink(shardHeader2, beaconHeader2, misbehaviour.Header2.CrossLinkIndex); err != nil {
		return sdkerrors.Wrap(err, "could not verify cross link of Header2")
	}

	epochState1, err := GetEpochState(clientStore, cdc, beaconHeader1.Epoch().Uint64())
	if err != nil {
		return sdkerrors.Wrapf(err, "could not get epoch state for Header1 at Epoch: %d", beaconHeader1.Epoch())
	}
	epochState2, err := GetEpochState(clientStore, cdc, beaconHeader2.Epoch().Uint64())
	if err != nil {
		return sdkerrors.Wrapf(err, "could not get epoch state for Header2 at Epoch: %d", beaconHeader2.Epoch())
	}
	if err := VerifyCommitSig(beaconHeader1, epochState1.GetCommittee(), bh1.CommitSig, bh1.CommitBitmap); err != nil {
		return sdkerrors.Wrap(err, "failed to verify committee signature of Header1")
	}
	if err := VerifyCommitSig(beaconHeader2, epochState2.GetCommittee(), bh2.CommitSig, bh2.CommitBitmap); err != nil {
		return sdkerrors.Wrap(err, "failed to verify committee signature of Header2")
	}
	return nil
}

func checkTimestamp(
	consTimestamp uint64,
	trustingPeriod time.Duration,
	current time.Time,
) error {
	consTime := timestampToUnix(consTimestamp)
	if current.Sub(consTime) >= trustingPeriod {
		return sdkerrors.Wrapf(
			ErrTrustingPeriodExpired,
			"current timestamp minus the header1 consensus state timestamp is greater than or equal to the trusting period (%d >= %d)",
			current.Sub(consTime), trustingPeriod,
		)
	}
	return nil
}

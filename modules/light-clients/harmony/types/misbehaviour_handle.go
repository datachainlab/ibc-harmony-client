package types

import (
	"bytes"
	time "time"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/harmony-one/harmony/block"
	v3 "github.com/harmony-one/harmony/block/v3"
	"github.com/harmony-one/harmony/shard"
)

// CheckMisbehaviourAndUpdateState detects the following as Misbehaviour:
//
// 1. The existence of two different valid beacon headers for the same beacon block number
// 2. The existence of two different valid shard headers for the same shard ID and block number:
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
	// Beacon header is always needed
	if hmyMisbehaviour.Header1 == nil || hmyMisbehaviour.Header1.BeaconHeader == nil {
		return nil, sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "Header1 is nil or does not have beacon header")
	}
	if hmyMisbehaviour.Header2 == nil || hmyMisbehaviour.Header2.BeaconHeader == nil {
		return nil, sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "Header2 is nil or does not have beacon header")
	}

	if cs.ShardId != shard.BeaconChainShardID {
		if len(hmyMisbehaviour.Header1.ShardHeader) == 0 || len(hmyMisbehaviour.Header2.ShardHeader) == 0 {
			return nil, sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "both shard headers cannot be empty")
		}
		// Both valid shard headers has the same block number
		if err := cs.CheckShardMisbehaviour(ctx, cdc, clientStore, hmyMisbehaviour); err != nil {
			return nil, err
		}
	} else {
		if len(hmyMisbehaviour.Header1.ShardHeader) != 0 || len(hmyMisbehaviour.Header2.ShardHeader) != 0 {
			return nil, sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "misbehaviour with a shard header is invalid for beacon")
		}
		// Both valid beacon headers has the same block number
		if err := cs.CheckBeaconMisbehaviour(ctx, cdc, clientStore, hmyMisbehaviour); err != nil {
			return nil, err
		}
	}

	cs.Frozen = true
	return &cs, nil
}

// CheckBeaconMisbehaviour checks the existence of two different valid beacon headers for the same beacon block number.
// It validates each header with the aggregated signature and its bitmap of the committee for the respective epoch.
func (cs ClientState) CheckBeaconMisbehaviour(
	ctx sdk.Context,
	cdc codec.BinaryCodec,
	clientStore sdk.KVStore,
	misbehaviour *Misbehaviour,
) error {
	bh1 := misbehaviour.Header1.BeaconHeader
	bh2 := misbehaviour.Header2.BeaconHeader
	header1, err := rlpDecodeHeader(bh1.Header)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode beacon header of Header1")
	}
	header2, err := rlpDecodeHeader(bh2.Header)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode beacon header of Header2")
	}

	// Check that both shard ids are for beacon
	if header1.ShardID() != shard.BeaconChainShardID {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 has wrong shard id. expected: %d, got: %d", shard.BeaconChainShardID, header1.ShardID())
	}
	if header2.ShardID() != shard.BeaconChainShardID {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header2 has wrong shard id. expected: %d, got: %d", shard.BeaconChainShardID, header2.ShardID())
	}
	// Ensure that Height1 epoch is equal to Height2
	if header1.Epoch().Cmp(header2.Epoch()) != 0 {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 epoch is not as same as Header2 epoch (%s != %s)", header1.Epoch(), header2.Epoch())
	}
	// Ensure that Height1 height is equal to Height2
	if header1.Number().Cmp(header2.Number()) != 0 {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 height is not as same as Header2 height (%s != %s)", header1.Number(), header2.Number())
	}

	// Check that both header is different
	b1 := block.Header{Header: header1}
	b2 := block.Header{Header: header2}
	if bytes.Equal(b1.Hash().Bytes(), b2.Hash().Bytes()) {
		return sdkerrors.Wrap(clienttypes.ErrInvalidMisbehaviour, "headers block hashes are equal")
	}

	// Check that both beacon headers are not too old to verify
	currentTimestamp := ctx.BlockTime()
	if err := cs.checkTargetShardTimestamp(cdc, clientStore, header1, currentTimestamp, 1); err != nil {
		return err
	}
	if err := cs.checkTargetShardTimestamp(cdc, clientStore, header2, currentTimestamp, 2); err != nil {
		return err
	}

	// Verify each beacon header with committee signatures.
	if err := cs.checkBeaconCommitSig(cdc, clientStore, header1, bh1.CommitSig, bh1.CommitBitmap, 1); err != nil {
		return err
	}
	if err := cs.checkBeaconCommitSig(cdc, clientStore, header2, bh2.CommitSig, bh2.CommitBitmap, 2); err != nil {
		return err
	}
	return nil
}

// CheckShardMisbehaviour checks for a case where two shard headers with the same block number are submitted
// Both shard headers assume the existence of a corresponding beacon header with a valid cross-link;
// a shard header without a cross-link is invalid in Harmony, and this light client does not accept it.
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

	// Check that both shard ids are for the shard id hold by ClientState
	if shardHeader1.ShardID() != cs.ShardId {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 shard header has wrong shard id. expected: %d, got: %d", cs.ShardId, shardHeader1.ShardID())
	}
	if shardHeader2.ShardID() != cs.ShardId {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header2 shard header has wrong shard id. expected: %d, got: %d", cs.ShardId, shardHeader2.ShardID())
	}
	// Ensure that Height1 epoch is equal to Height2
	if shardHeader1.Epoch().Cmp(shardHeader2.Epoch()) != 0 {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 epoch is not as same as Header2 epoch (%s != %s)", shardHeader1.Epoch(), shardHeader2.Epoch())
	}
	// Ensure that Height1 height is equal to Height2
	if shardHeader1.Number().Cmp(shardHeader2.Number()) != 0 {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 height is not as same as Header2 height (%s != %s)", shardHeader1.Number(), shardHeader2.Number())
	}

	// Check that both target headers are not too old to verify
	currentTimestamp := ctx.BlockTime()
	if err := cs.checkTargetShardTimestamp(cdc, clientStore, shardHeader1, currentTimestamp, 1); err != nil {
		return err
	}
	if err := cs.checkTargetShardTimestamp(cdc, clientStore, shardHeader2, currentTimestamp, 2); err != nil {
		return err
	}

	bh1 := misbehaviour.Header1.BeaconHeader
	bh2 := misbehaviour.Header2.BeaconHeader
	beaconHeader1, err := rlpDecodeHeader(bh1.Header)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode beacon header of Header1")
	}
	beaconHeader2, err := rlpDecodeHeader(bh2.Header)
	if err != nil {
		return sdkerrors.Wrap(err, "could not decode beacon header of Header1")
	}
	// Check that both shard ids are for beacon
	if beaconHeader1.ShardID() != shard.BeaconChainShardID {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 beacon header has wrong shard id. expected: %d, got: %d", shard.BeaconChainShardID, beaconHeader1.ShardID())
	}
	if beaconHeader2.ShardID() != shard.BeaconChainShardID {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header2 beacon header has wrong shard id. expected: %d, got: %d", shard.BeaconChainShardID, beaconHeader2.ShardID())
	}

	// Check that each cross-link is valid
	if err := checkCrossLink(shardHeader1, beaconHeader1, misbehaviour.Header1.CrossLinkIndex); err != nil {
		return sdkerrors.Wrap(err, "could not verify cross link of Header1")
	}
	if err := checkCrossLink(shardHeader2, beaconHeader2, misbehaviour.Header2.CrossLinkIndex); err != nil {
		return sdkerrors.Wrap(err, "could not verify cross link of Header2")
	}

	// Verify each beacon header with committee signatures.
	if err := cs.checkBeaconCommitSig(cdc, clientStore, beaconHeader1, bh1.CommitSig, bh1.CommitBitmap, 1); err != nil {
		return err
	}
	if err := cs.checkBeaconCommitSig(cdc, clientStore, beaconHeader2, bh2.CommitSig, bh2.CommitBitmap, 2); err != nil {
		return err
	}
	return nil
}

func (cs ClientState) checkTargetShardTimestamp(
	cdc codec.BinaryCodec,
	clientStore sdk.KVStore,
	header *v3.Header,
	timestamp time.Time,
	headerIndex int,
) error {
	height := clienttypes.NewHeight(cs.LatestHeight.RevisionNumber, header.Number().Uint64())
	hmyConsensusState, err := GetConsensusState(clientStore, cdc, height)
	if err != nil {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidMisbehaviour,
			"could not get consensus state from clientStore for Header%d at Height: %s", headerIndex, height)
	}
	if err := checkTimestamp(hmyConsensusState.Timestamp, cs.TrustingPeriod, timestamp); err != nil {
		return err
	}
	return nil
}

// checkBeaconCommitSig verifies that `header` is a valid beacon header with sufficient signatures.
// Each epoch state has the beacon committee for the corresponding epoch.
func (cs ClientState) checkBeaconCommitSig(
	cdc codec.BinaryCodec,
	clientStore sdk.KVStore,
	header *v3.Header,
	commitSig []byte,
	commitBitmap []byte,
	headerIndex int,
) error {
	epochState, err := GetEpochState(clientStore, cdc, header.Epoch().Uint64())
	if err != nil {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidMisbehaviour,
			"could not get epoch state for Header%d at Epoch: %d: %w", headerIndex, header.Epoch(), err)
	}
	if err := VerifyCommitSig(header, epochState.GetCommittee(), commitSig, commitBitmap); err != nil {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidMisbehaviour,
			"failed to verify committee signature of Header%d: %w", headerIndex, err)
	}
	return nil
}

// checkTimestamp checks that misbehaviour headers are not too old to verify
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

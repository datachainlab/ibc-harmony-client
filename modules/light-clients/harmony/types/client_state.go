package types

import (
	"fmt"

	ics23 "github.com/confio/ics23/go"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/rlp"
	v3 "github.com/harmony-one/harmony/block/v3"
	"github.com/harmony-one/harmony/consensus/signature"
	hmytypes "github.com/harmony-one/harmony/core/types"
	"github.com/harmony-one/harmony/crypto/bls"
	"github.com/harmony-one/harmony/shard"
)

var _ exported.ClientState = (*ClientState)(nil)

func NewClientState() *ClientState {
	return &ClientState{}
}

func (cs ClientState) ClientType() string {
	return HarmonyClient
}

func (cs ClientState) GetLatestHeight() exported.Height {
	return cs.LatestHeight
}

func (cs ClientState) Validate() error {
	if len(cs.ContractAddress) == 0 {
		return fmt.Errorf("ContractAddress is empty")
	}
	return nil
}

func (cs ClientState) GetProofSpecs() []*ics23.ProofSpec {
	return nil
}

// Initialization function
// Clients must validate the initial consensus state, and may store any client-specific metadata
// necessary for correct light client operation
func (cs ClientState) Initialize(ctx sdk.Context, cdc codec.BinaryCodec, store sdk.KVStore, consState exported.ConsensusState) error {
	if _, ok := consState.(*ConsensusState); !ok {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidConsensus, "invalid initial consensus state. expected type: %T, got: %T",
			&ConsensusState{}, consState)
	}
	// TODO set metada for initial consensus state
	SetEpochState(store, cdc, &EpochState{Committee: cs.LatestCommittee}, cs.LatestEpoch)
	return nil
}

// Status function
// Clients must return their status. Only Active clients are allowed to process packets.
func (cs ClientState) Status(ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec) exported.Status {
	// TODO add frozen status support
	return exported.Active
}

// Genesis function
func (cs ClientState) ExportMetadata(_ sdk.KVStore) []exported.GenesisMetadata {
	return nil
}

// Update and Misbehaviour functions
func (cs ClientState) CheckHeaderAndUpdateState(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore,
	header exported.Header,
) (exported.ClientState, exported.ConsensusState, error) {
	h, ok := header.(*Header)
	if !ok {
		return nil, nil, sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader, "expected type %T, got %T", &Header{}, header,
		)
	}
	beaconHeader, err := rlpDecodeHeader(h.BeaconHeader)
	if err != nil {
		return nil, nil, err
	}
	var targetHeader *v3.Header
	if cs.ShardId == 0 {
		targetHeader = beaconHeader
	} else {
		shardHeader, err := rlpDecodeHeader(h.ShardHeader)
		if err != nil {
			return nil, nil, err
		}
		// verify the existence of crossLink in the beacon header
		var crossLinks hmytypes.CrossLinks
		if err := rlp.DecodeBytes(beaconHeader.CrossLinks(), &crossLinks); err != nil {
			return nil, nil, err
		}
		if len(crossLinks) <= int(h.CrossLinkIndex) {
			return nil, nil, fmt.Errorf("invalid crossLink index: %v < %v", len(crossLinks), h.CrossLinkIndex)
		}
		if shardHeader.Hash() != crossLinks[h.CrossLinkIndex].HashF {
			return nil, nil, fmt.Errorf("unexpected shard header: expected=%v actual=%v", shardHeader.Hash().Hex(), crossLinks[h.CrossLinkIndex].HashF.Hex())
		}
		targetHeader = shardHeader
	}
	if l := len(beaconHeader.ShardState()); l > 0 {
		// epoch change
		return cs.updateEpoch(ctx, cdc, clientStore, h, beaconHeader, targetHeader)
	} else {
		// only height change
		return cs.updateHeight(ctx, cdc, clientStore, h, beaconHeader, targetHeader)
	}
}

func (cs ClientState) CheckMisbehaviourAndUpdateState(_ sdk.Context, _ codec.BinaryCodec, _ sdk.KVStore, _ exported.Misbehaviour) (exported.ClientState, error) {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) CheckSubstituteAndUpdateState(ctx sdk.Context, cdc codec.BinaryCodec, subjectClientStore sdk.KVStore, substituteClientStore sdk.KVStore, substituteClient exported.ClientState) (exported.ClientState, error) {
	panic("not implemented") // TODO: Implement
}

// Upgrade functions
// NOTE: proof heights are not included as upgrade to a new revision is expected to pass only on the last
// height committed by the current revision. Clients are responsible for ensuring that the planned last
// height of the current revision is somehow encoded in the proof verification process.
// This is to ensure that no premature upgrades occur, since upgrade plans committed to by the counterparty
// may be cancelled or modified before the last planned height.
func (cs ClientState) VerifyUpgradeAndUpdateState(ctx sdk.Context, cdc codec.BinaryCodec, store sdk.KVStore, newClient exported.ClientState, newConsState exported.ConsensusState, proofUpgradeClient []byte, proofUpgradeConsState []byte) (exported.ClientState, exported.ConsensusState, error) {
	panic("not implemented") // TODO: Implement
}

// Utility function that zeroes out any client customizable fields in client state
// Ledger enforced fields are maintained while all custom fields are zero values
// Used to verify upgrades
func (cs ClientState) ZeroCustomFields() exported.ClientState {
	panic("not implemented") // TODO: Implement
}

// State verification functions
func (cs ClientState) VerifyClientState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, prefix exported.Prefix, counterpartyClientIdentifier string, proof []byte, clientState exported.ClientState) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyClientConsensusState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, counterpartyClientIdentifier string, consensusHeight exported.Height, prefix exported.Prefix, proof []byte, consensusState exported.ConsensusState) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyConnectionState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, prefix exported.Prefix, proof []byte, connectionID string, connectionEnd exported.ConnectionI) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyChannelState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, prefix exported.Prefix, proof []byte, portID string, channelID string, channel exported.ChannelI) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyPacketCommitment(ctx sdk.Context, store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, prefix exported.Prefix, proof []byte, portID string, channelID string, sequence uint64, commitmentBytes []byte) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyPacketAcknowledgement(ctx sdk.Context, store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, prefix exported.Prefix, proof []byte, portID string, channelID string, sequence uint64, acknowledgement []byte) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyPacketReceiptAbsence(ctx sdk.Context, store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, prefix exported.Prefix, proof []byte, portID string, channelID string, sequence uint64) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) VerifyNextSequenceRecv(ctx sdk.Context, store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, prefix exported.Prefix, proof []byte, portID string, channelID string, nextSequenceRecv uint64) error {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) GetCommittee() *shard.Committee {
	var committee shard.Committee
	if err := rlp.DecodeBytes(cs.LatestCommittee, &committee); err != nil {
		panic(err)
	}
	return &committee
}

func (cs *ClientState) SetCommittee(committee *shard.Committee) {
	bz, err := rlp.EncodeToBytes(committee)
	if err != nil {
		panic(err)
	}
	cs.LatestCommittee = bz
}

func (cs ClientState) updateHeight(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore,
	header *Header,
	beaconHeader *v3.Header,
	targetHeader *v3.Header,
) (exported.ClientState, exported.ConsensusState, error) {
	panic("not implemented") // TODO: Implement
}

func (cs ClientState) updateEpoch(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore,
	header *Header,
	beaconHeader *v3.Header,
	targetHeader *v3.Header,
) (exported.ClientState, exported.ConsensusState, error) {
	proof, err := header.GetAccountProof()
	if err != nil {
		return nil, nil, err
	}
	account, err := VerifyProof(targetHeader.Root(), cs.ContractAddress, proof)
	if err != nil {
		return nil, nil, err
	}
	storageRoot, err := extractStorageRootFromAccount(account)
	if err != nil {
		return nil, nil, err
	}
	epochState, err := GetEpochState(clientStore, cdc, beaconHeader.Epoch().Uint64())
	if err != nil {
		return nil, nil, err
	}
	keys, err := epochState.GetCommittee().BLSPublicKeys()
	if err != nil {
		return nil, nil, err
	}
	mask, err := bls.NewMask(keys, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := mask.SetMask(header.Bitmap); err != nil {
		return nil, nil, err
	}
	aggSig, err := header.GetSignature()
	if err != nil {
		return nil, nil, err
	}
	// TODO set signatureSignReader
	payload := signature.ConstructCommitPayload(nil, beaconHeader.Epoch(), beaconHeader.Hash(), beaconHeader.Number().Uint64(), beaconHeader.ViewID().Uint64())
	if !aggSig.VerifyHash(mask.AggregatePublic, payload) {
		return nil, nil, fmt.Errorf("failed to verify the multi signature")
	}
	var shardState shard.State
	if err := rlp.DecodeBytes(beaconHeader.ShardState(), &shardState); err != nil {
		return nil, nil, err
	}
	commitee, ok := lookupCommitteeByID(shardState.Shards, cs.ShardId)
	if !ok {
		return nil, nil, fmt.Errorf("shard %v not found", cs.ShardId)
	}
	cs.LatestEpoch += 1
	cs.LatestHeight = &clienttypes.Height{RevisionNumber: cs.LatestHeight.RevisionNumber, RevisionHeight: targetHeader.Number().Uint64()}
	cs.SetCommittee(commitee)
	SetEpochState(clientStore, cdc, &EpochState{Committee: cs.LatestCommittee}, cs.LatestEpoch)
	return &cs, &ConsensusState{
		Timestamp: beaconHeader.Time().Uint64(),
		Root:      storageRoot,
	}, nil
}

func lookupCommitteeByID(shards []shard.Committee, targetID uint32) (*shard.Committee, bool) {
	for _, shard := range shards {
		if shard.ShardID == targetID {
			return &shard, true
		}
	}
	return nil, false
}

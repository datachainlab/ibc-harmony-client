package types

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	time "time"

	ics23 "github.com/confio/ics23/go"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	connectiontypes "github.com/cosmos/ibc-go/modules/core/03-connection/types"
	channeltypes "github.com/cosmos/ibc-go/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/modules/core/23-commitment/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	bls_core "github.com/harmony-one/bls/ffi/go/bls"
	"github.com/harmony-one/harmony/block"
	v3 "github.com/harmony-one/harmony/block/v3"
	"github.com/harmony-one/harmony/consensus/quorum"
	hmytypes "github.com/harmony-one/harmony/core/types"
	"github.com/harmony-one/harmony/crypto/bls"
	"github.com/harmony-one/harmony/shard"
)

const (
	// We make an presumption that it is after StakingEpoch.
	isStaking = true

	beaconShardId = 0
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
		return fmt.Errorf("ContractAddress cannot be empty")
	}
	if len(cs.LatestCommittee) == 0 {
		return fmt.Errorf("LatestCommittee cannot be empty")
	}
	if cs.LatestHeight.RevisionHeight == 0 {
		return errors.New("LatestHeight RevisionHeight cannot be 0")
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
	// TODO set metadata for initial consensus state
	SetEpochState(store, cdc, &EpochState{Committee: cs.LatestCommittee}, cs.LatestEpoch)
	return nil
}

// Status function
// Clients must return their status. Only Active clients are allowed to process packets.
func (cs ClientState) Status(ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec) exported.Status {
	if cs.Frozen {
		return exported.Frozen
	}
	// get latest consensus state from clientStore to check for expiry
	consState, err := GetConsensusState(clientStore, cdc, cs.GetLatestHeight())
	if err != nil {
		return exported.Unknown
	}

	if cs.IsExpired(timestampToUnix(consState.Timestamp), ctx.BlockTime()) {
		return exported.Expired
	}

	return exported.Active
}

// IsExpired returns whether or not the client has passed the trusting period since the last
// update (in which case no headers are considered valid).
func (cs ClientState) IsExpired(latestTimestamp, now time.Time) bool {
	expirationTime := latestTimestamp.Add(cs.TrustingPeriod)
	return !expirationTime.After(now)
}

// Genesis function
func (cs ClientState) ExportMetadata(_ sdk.KVStore) []exported.GenesisMetadata {
	return nil
}

// CheckHeaderAndUpdateState verifies that:
// - the beacon header with the associated committee signature and bitmap. It also verifies the quorum using the committee of the target epoch.
// - (for shard 1+) the shard header with the cross-link of the beacon header.
// If the target header's epoch is older than the epoch of ClientState,
// `header` must have "epoch header(s)", which is/are the last beacon header(s) of each epoch for updating epoch of ClientState.
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
	// Update epoch(s) before verifying the last beacon header
	for _, bh := range h.EpochHeaders {
		if err := cs.updateEpochOnly(ctx, cdc, clientStore, &bh); err != nil {
			return nil, nil, err
		}
	}
	return cs.update(ctx, cdc, clientStore, h, h.BeaconHeader)
}

// Future work is needed
func (cs ClientState) CheckSubstituteAndUpdateState(ctx sdk.Context, cdc codec.BinaryCodec, subjectClientStore sdk.KVStore, substituteClientStore sdk.KVStore, substituteClient exported.ClientState) (exported.ClientState, error) {
	return nil, sdkerrors.Wrapf(
		clienttypes.ErrUpdateClientFailed,
		"harmony client is not allowed to updated with a proposal",
	)
}

// Future work is needed
func (cs ClientState) VerifyUpgradeAndUpdateState(ctx sdk.Context, cdc codec.BinaryCodec, store sdk.KVStore, newClient exported.ClientState, newConsState exported.ConsensusState, proofUpgradeClient []byte, proofUpgradeConsState []byte) (exported.ClientState, exported.ConsensusState, error) {
	return nil, nil, sdkerrors.Wrap(clienttypes.ErrInvalidUpgradeClient, "cannot upgrade harmony client")
}

// Utility function that zeroes out any client customizable fields in client state
// Ledger enforced fields are maintained while all custom fields are zero values
// Used to verify upgrades
func (cs ClientState) ZeroCustomFields() exported.ClientState {
	return &ClientState{
		ShardId:         cs.ShardId,
		ContractAddress: cs.ContractAddress,
		LatestEpoch:     cs.LatestEpoch,
		LatestCommittee: cs.LatestCommittee,
		LatestHeight:    cs.LatestHeight,
	}
}

// State verification functions
func (cs ClientState) VerifyClientState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, prefix exported.Prefix, counterpartyClientIdentifier string, proof []byte, clientState exported.ClientState) error {
	merkleProof, provingConsensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}

	root := common.BytesToHash(provingConsensusState.Root)
	slot, err := ClientStateCommitmentSlot(counterpartyClientIdentifier)
	if err != nil {
		return err
	}

	if clientState == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidClient, "client state cannot be empty")
	}

	bz, err := cdc.MarshalInterface(clientState)
	if err != nil {
		return err
	}

	return VerifyStorageProof(root, slot, crypto.Keccak256(bz), merkleProof)
}

func (cs ClientState) VerifyClientConsensusState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, counterpartyClientIdentifier string, consensusHeight exported.Height, prefix exported.Prefix, proof []byte, consensusState exported.ConsensusState) error {
	merkleProof, provingConsensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}

	root := common.BytesToHash(provingConsensusState.Root)
	slot, err := ConsensusStateCommitmentSlot(counterpartyClientIdentifier, consensusHeight)
	if err != nil {
		return err
	}

	if consensusState == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidConsensus, "consensus state cannot be empty")
	}

	bz, err := cdc.MarshalInterface(consensusState)
	if err != nil {
		return err
	}

	return VerifyStorageProof(root, slot, crypto.Keccak256(bz), merkleProof)
}

func (cs ClientState) VerifyConnectionState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, prefix exported.Prefix, proof []byte, connectionID string, connectionEnd exported.ConnectionI) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}

	root := common.BytesToHash(consensusState.Root)
	slot, err := ConnectionCommitmentSlot(connectionID)
	if err != nil {
		return err
	}

	connection, ok := connectionEnd.(connectiontypes.ConnectionEnd)
	if !ok {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "invalid connection type %T", connectionEnd)
	}

	bz, err := cdc.Marshal(&connection)
	if err != nil {
		return err
	}

	return VerifyStorageProof(root, slot, crypto.Keccak256(bz), merkleProof)
}

func (cs ClientState) VerifyChannelState(store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, prefix exported.Prefix, proof []byte, portID string, channelID string, channel exported.ChannelI) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}
	root := common.BytesToHash(consensusState.Root)
	slot, err := ChannelCommitmentSlot(portID, channelID)
	if err != nil {
		return err
	}

	channelEnd, ok := channel.(channeltypes.Channel)
	if !ok {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "invalid channel type %T", channel)
	}

	bz, err := cdc.Marshal(&channelEnd)
	if err != nil {
		return err
	}

	return VerifyStorageProof(root, slot, crypto.Keccak256(bz), merkleProof)
}

func (cs ClientState) VerifyPacketCommitment(ctx sdk.Context, store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, prefix exported.Prefix, proof []byte, portID string, channelID string, sequence uint64, commitmentBytes []byte) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}
	root := common.BytesToHash(consensusState.Root)
	slot, err := PacketCommitmentSlot(portID, channelID, sequence)
	if err != nil {
		return err
	}

	return VerifyStorageProof(root, slot, commitmentBytes, merkleProof)
}

func (cs ClientState) VerifyPacketAcknowledgement(ctx sdk.Context, store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, prefix exported.Prefix, proof []byte, portID string, channelID string, sequence uint64, acknowledgement []byte) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}
	root := common.BytesToHash(consensusState.Root)
	slot, err := PacketAcknowledgementCommitmentSlot(portID, channelID, sequence)
	if err != nil {
		return err
	}

	v := sha256.Sum256(acknowledgement)
	return VerifyStorageProof(root, slot, v[:], merkleProof)
}

func (cs ClientState) VerifyPacketReceiptAbsence(ctx sdk.Context, store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, prefix exported.Prefix, proof []byte, portID string, channelID string, sequence uint64) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}
	root := common.BytesToHash(consensusState.Root)
	slot, err := PacketReceiptCommitmentSlot(portID, channelID, sequence)
	if err != nil {
		return err
	}
	// verify non-membership
	return VerifyStorageProof(root, slot, nil, merkleProof)
}

func (cs ClientState) VerifyNextSequenceRecv(ctx sdk.Context, store sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, prefix exported.Prefix, proof []byte, portID string, channelID string, nextSequenceRecv uint64) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}
	root := common.BytesToHash(consensusState.Root)
	slot, err := NextSequenceRecvCommitmentSlot(portID, channelID)
	if err != nil {
		return err
	}
	bz := sdk.Uint64ToBigEndian(nextSequenceRecv)
	return VerifyStorageProof(root, slot, bz, merkleProof)
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

// updateEpochOnly increases the epoch of ClientState by one
// using the last beacon header of the same epoch.
func (cs *ClientState) updateEpochOnly(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore,
	beacon *BeaconHeader,
) error {
	beaconHeader, err := rlpDecodeHeader(beacon.Header)
	if err != nil {
		return err
	}
	if beaconHeader.ShardID() != shard.BeaconChainShardID {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader, "beacon shard id must be %d", shard.BeaconChainShardID)
	}
	epoch := beaconHeader.Epoch().Uint64()
	if epoch != cs.LatestEpoch {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader, "beacon epoch %d != latest epoch %d", epoch, cs.LatestEpoch,
		)
	}
	// Get the target epoch committee for verifying the aggregated signature for the header
	epochState, err := GetEpochState(clientStore, cdc, epoch)
	if err != nil {
		return err
	}
	committee := epochState.GetCommittee()
	if err := VerifyCommitSig(beaconHeader, committee, beacon.CommitSig, beacon.CommitBitmap); err != nil {
		return err
	}

	// Ensure the header is the last header for an epoch
	if len(beaconHeader.ShardState()) == 0 {
		return sdkerrors.Wrap(
			clienttypes.ErrInvalidHeader, "beacon headers except the last one must have shard state")
	}
	var shardState shard.State
	if err := rlp.DecodeBytes(beaconHeader.ShardState(), &shardState); err != nil {
		return err
	}
	newCommitee, ok := lookupBeaconCommittee(shardState.Shards)
	if !ok {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader, "shard %v not found", cs.ShardId)
	}
	cs.LatestEpoch += 1
	cs.SetCommittee(newCommitee)
	// Store for use in header validation of the same epoch
	SetEpochState(clientStore, cdc, &EpochState{Committee: cs.LatestCommittee}, cs.LatestEpoch)
	return nil
}

// update verifies the target header and updates the height of ClientState.
func (cs *ClientState) update(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore,
	header *Header,
	beacon *BeaconHeader,
) (exported.ClientState, exported.ConsensusState, error) {
	beaconHeader, err := rlpDecodeHeader(beacon.Header)
	if err != nil {
		return nil, nil, err
	}
	if beaconHeader.ShardID() != shard.BeaconChainShardID {
		return nil, nil, sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader, "beacon shard id must be %d", shard.BeaconChainShardID)
	}

	var targetHeader *v3.Header
	// If shard id is non-zero, Header has a shard header.
	// Verify that the cross-link corresponding to the shard header is present in the beacon header submitted with it.
	if cs.ShardId != shard.BeaconChainShardID {
		if len(header.ShardHeader) == 0 {
			return nil, nil, sdkerrors.Wrapf(
				clienttypes.ErrInvalidHeader, "shard header cannot be nil")
		}
		shardHeader, err := rlpDecodeHeader(header.ShardHeader)
		if err != nil {
			return nil, nil, err
		}
		if shardHeader.ShardID() != cs.ShardId {
			return nil, nil, sdkerrors.Wrapf(
				clienttypes.ErrInvalidHeader, "target shard id must be %d", cs.ShardId)
		}
		if err := checkCrossLink(shardHeader, beaconHeader, header.CrossLinkIndex); err != nil {
			return nil, nil, err
		}
		targetHeader = shardHeader
	} else {
		targetHeader = beaconHeader
	}

	// Verify the account proof for the target contract address and get the storage root
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

	// Verify the beacon header with aggregated signature of the committee for the latest epoch of ClientState.
	epoch := beaconHeader.Epoch().Uint64()
	if cs.LatestEpoch != epoch {
		return nil, nil, sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader, "invalid beacon epoch %d: expected: %d", epoch, cs.LatestEpoch)
	}
	epochState, err := GetEpochState(clientStore, cdc, epoch)
	if err != nil {
		return nil, nil, err
	}
	committee := epochState.GetCommittee()
	if err := VerifyCommitSig(beaconHeader, committee, beacon.CommitSig, beacon.CommitBitmap); err != nil {
		return nil, nil, err
	}

	// If shard state exists, the beacon header is the last header of this epoch.
	// Update committee to accept the next epoch's header
	if len(beaconHeader.ShardState()) > 0 {
		var shardState shard.State
		if err := rlp.DecodeBytes(beaconHeader.ShardState(), &shardState); err != nil {
			return nil, nil, err
		}
		newCommitee, ok := lookupBeaconCommittee(shardState.Shards)
		if !ok {
			return nil, nil, sdkerrors.Wrapf(clienttypes.ErrInvalidHeader, "shard %v not found", cs.ShardId)
		}
		cs.LatestEpoch += 1
		cs.SetCommittee(newCommitee)
		SetEpochState(clientStore, cdc, &EpochState{Committee: cs.LatestCommittee}, cs.LatestEpoch)
	}

	height := clienttypes.Height{
		RevisionNumber: cs.LatestHeight.RevisionNumber,
		RevisionHeight: targetHeader.Number().Uint64(),
	}
	if !cs.LatestHeight.GTE(height) {
		cs.LatestHeight = height
	}
	return cs, &ConsensusState{
		Timestamp: targetHeader.Time().Uint64(),
		Root:      storageRoot,
	}, nil
}

func VerifyCommitSig(
	beaconHeader *v3.Header,
	committee *shard.Committee,
	commitSig, commitBitmap []byte,
) error {
	keys, err := committee.BLSPublicKeys()
	if err != nil {
		return err
	}
	mask, err := bls.NewMask(keys, nil)
	if err != nil {
		return err
	}
	if err := mask.SetMask(commitBitmap); err != nil {
		return err
	}
	epoch := beaconHeader.Epoch()
	qrVerifier, err := quorum.NewVerifier(committee, epoch, isStaking)
	if err != nil {
		return err
	}
	if !qrVerifier.IsQuorumAchievedByMask(mask) {
		return sdkerrors.Wrap(ErrInvalidSignature, "not enough signature collected")
	}
	aggSig, err := decodeSignature(commitSig[:])
	if err != nil {
		return err
	}
	blockHeader := block.Header{Header: beaconHeader}
	payload := ConstructCommitPayload(blockHeader.Hash(), beaconHeader.Number().Uint64(), beaconHeader.ViewID().Uint64())
	if !aggSig.VerifyHash(mask.AggregatePublic, payload) {
		return sdkerrors.Wrap(ErrInvalidSignature, "failed to verify the multi signature")
	}
	return nil
}

func lookupBeaconCommittee(shards []shard.Committee) (*shard.Committee, bool) {
	for _, s := range shards {
		if s.ShardID == shard.BeaconChainShardID {
			return &s, true
		}
	}
	return nil, false
}

// produceVerificationArgs perfoms the basic checks on the arguments that are
// shared between the verification functions and returns the unmarshalled
// merkle proof, the consensus state and an error if one occurred.
func produceVerificationArgs(
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	cs ClientState,
	height exported.Height,
	prefix exported.Prefix,
	proof []byte,
) (merkleProof [][]byte, consensusState *ConsensusState, err error) {
	if cs.GetLatestHeight().LT(height) {
		return nil, nil, sdkerrors.Wrapf(
			sdkerrors.ErrInvalidHeight,
			"client state height < proof height (%d < %d), please ensure the client has been updated", cs.GetLatestHeight(), height)
	}

	if prefix == nil {
		return nil, nil, sdkerrors.Wrap(commitmenttypes.ErrInvalidPrefix, "prefix cannot be empty")
	}

	_, ok := prefix.(*commitmenttypes.MerklePrefix)
	if !ok {
		return nil, nil, sdkerrors.Wrapf(commitmenttypes.ErrInvalidPrefix, "invalid prefix type %T, expected *MerklePrefix", prefix)
	}

	if proof == nil {
		return nil, nil, sdkerrors.Wrap(commitmenttypes.ErrInvalidProof, "proof cannot be empty")
	}

	merkleProof, err = decodeRLP(proof)
	if err != nil {
		return nil, nil, sdkerrors.Wrap(commitmenttypes.ErrInvalidProof, "failed to unmarshal proof into commitment merkle proof")
	}

	consensusState, err = GetConsensusState(store, cdc, height)
	if err != nil {
		return nil, nil, sdkerrors.Wrap(err, "please ensure the proof was constructed against a height that exists on the client")
	}

	return merkleProof, consensusState, nil
}

// verify crossLink in the beacon header with matching hash
func checkCrossLink(shardHeader, beaconHeader *v3.Header, crossLinkIndex uint32) error {
	var crossLinks hmytypes.CrossLinks
	if err := rlp.DecodeBytes(beaconHeader.CrossLinks(), &crossLinks); err != nil {
		return err
	}
	if int(crossLinkIndex) >= len(crossLinks) {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader,
			"invalid crosslink: index %d is greater than or equal to length %d", crossLinkIndex, len(crossLinks))
	}
	shardBlockHeader := block.Header{Header: shardHeader}
	if !bytes.Equal(shardBlockHeader.Hash().Bytes(), crossLinks[crossLinkIndex].HashF.Bytes()) {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader,
			"unexpected shard hash for crosslink: expected=%v actual=%v", crossLinks[crossLinkIndex].HashF.Hex(), shardHeader.Hash().Hex())
	}
	return nil
}

func decodeSignature(sig []byte) (*bls_core.Sign, error) {
	var sign bls_core.Sign
	if err := sign.Deserialize(sig); err != nil {
		return nil, err
	}
	return &sign, nil
}

func timestampToUnix(timestamp uint64) time.Time {
	return time.Unix(int64(timestamp), 0)
}

package types

import (
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/modules/core/24-host"
	"github.com/cosmos/ibc-go/modules/core/exported"
)

var _ exported.Misbehaviour = &Misbehaviour{}

// ClientType is a Multisig light client.
func (misbehaviour Misbehaviour) ClientType() string {
	return HarmonyClient
}

// GetClientID returns the ID of the client that committed a misbehaviour.
func (misbehaviour Misbehaviour) GetClientID() string {
	return misbehaviour.ClientId
}

// Type implements Evidence interface.
func (misbehaviour Misbehaviour) Type() string {
	return exported.TypeClientMisbehaviour
}

// ValidateBasic implements Evidence interface.
func (misbehaviour Misbehaviour) ValidateBasic() error {
	if misbehaviour.Header1 == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "misbehaviour Header1 cannot be nil")
	}
	if misbehaviour.Header2 == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidHeader, "misbehaviour Header2 cannot be nil")
	}

	if err := host.ClientIdentifierValidator(misbehaviour.ClientId); err != nil {
		return sdkerrors.Wrap(err, "invalid client identifier")
	}

	if err := misbehaviour.Header1.ValidateBasic(); err != nil {
		return sdkerrors.Wrap(
			clienttypes.ErrInvalidMisbehaviour,
			sdkerrors.Wrap(err, "header 1 failed validation").Error(),
		)
	}
	if err := misbehaviour.Header2.ValidateBasic(); err != nil {
		return sdkerrors.Wrap(
			clienttypes.ErrInvalidMisbehaviour,
			sdkerrors.Wrap(err, "header 2 failed validation").Error(),
		)
	}

	// Ensure that Height1 epoch is equal to Height2
	if misbehaviour.Header1.GetEpoch().Cmp(misbehaviour.Header2.GetEpoch()) != 0 {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 epoch is not as same as Header2 epoch (%s != %s)", misbehaviour.Header1.GetEpoch(), misbehaviour.Header2.GetEpoch())
	}
	// Ensure that Height1 height is equal to Height2
	if !misbehaviour.Header1.GetHeight().EQ(misbehaviour.Header2.GetHeight()) {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidMisbehaviour, "Header1 height is not as same as Header2 height (%s != %s)", misbehaviour.Header1.GetHeight(), misbehaviour.Header2.GetHeight())
	}

	// Check that each misbehaviour header has no epoch header
	// because it is unnecessary to construct a misbehaviour.
	if len(misbehaviour.Header1.EpochHeaders) != 0 {
		return sdkerrors.Wrap(
			clienttypes.ErrInvalidMisbehaviour, "Header1 with epoch headers cannot be accepted")
	}
	if len(misbehaviour.Header2.EpochHeaders) != 0 {
		return sdkerrors.Wrap(
			clienttypes.ErrInvalidMisbehaviour, "Header2 with epoch headers cannot be accepted")
	}
	return nil
}

package types

import (
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// Harmony client sentinel errors
var (
	ErrEpochStateNotFound    = sdkerrors.Register(ModuleName, 1, "epoch state not found")
	ErrInvalidProof          = sdkerrors.Register(ModuleName, 2, "invalid proof")
	ErrInvalidSignature      = sdkerrors.Register(ModuleName, 3, "invalid signature")
	ErrTrustingPeriodExpired = sdkerrors.Register(ModuleName, 4, "time since latest trusted state has passed the trusting period")
)

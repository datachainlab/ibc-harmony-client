package types

import (
	"bytes"
	"errors"
	"math/big"

	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/rlp"
	v3 "github.com/harmony-one/harmony/block/v3"
)

var _ exported.Header = (*Header)(nil)

func (h Header) ClientType() string {
	return HarmonyClient
}

// GetHeight returns the target height
func (h Header) GetHeight() exported.Height {
	header, err := h.decode()
	if err != nil {
		panic(err)
	}
	return clienttypes.NewHeight(0, header.Number().Uint64())
}

func (h Header) ValidateBasic() error {
	if len(h.BeaconHeaders) == 0 {
		return errors.New("beacon header cannot be empty")
	}
	if len(h.ShardHeader) > 0 {
		if len(h.AccountProof) == 0 {
			return errors.New("AccountProof is empty")
		}
	}
	return nil
}

func (h Header) GetAccountProof() ([][]byte, error) {
	return decodeRLP(h.AccountProof)
}

// GetEpoch returns the target epoch
func (h Header) GetEpoch() *big.Int {
	header, err := h.decode()
	if err != nil {
		panic(err)
	}
	return header.Epoch()
}

// GetEpoch returns the last beacon epoch
func (h Header) GetBeaconEpoch() *big.Int {
	header, err := rlpDecodeHeader(h.BeaconHeaders[len(h.BeaconHeaders)-1].Header)
	if err != nil {
		panic(err)
	}
	return header.Epoch()
}

func (h Header) decode() (*v3.Header, error) {
	var header *v3.Header
	var err error
	if len(h.ShardHeader) > 0 {
		header, err = rlpDecodeHeader(h.ShardHeader)
		if err != nil {
			return nil, err
		}
	} else {
		header, err = rlpDecodeHeader(h.BeaconHeaders[len(h.BeaconHeaders)-1].Header)
		if err != nil {
			return nil, err
		}
	}
	return header, nil
}

func rlpDecodeHeader(bz []byte) (*v3.Header, error) {
	var header v3.Header
	r := bytes.NewReader(bz)
	s := rlp.NewStream(r, 0)
	if err := header.DecodeRLP(s); err != nil {
		return nil, err
	}
	return &header, nil
}

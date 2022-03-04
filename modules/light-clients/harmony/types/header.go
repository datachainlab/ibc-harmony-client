package types

import (
	"bytes"
	"fmt"

	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/rlp"
	bls_core "github.com/harmony-one/bls/ffi/go/bls"
	v3 "github.com/harmony-one/harmony/block/v3"
	"github.com/harmony-one/harmony/crypto/bls"
)

var _ exported.Header = (*Header)(nil)

func (h Header) ClientType() string {
	return HarmonyClient
}

func (h Header) GetHeight() exported.Height {
	header, err := rlpDecodeHeader(h.ShardHeader)
	if err != nil {
		panic(err)
	}
	return clienttypes.NewHeight(0, header.Number().Uint64())
}

func (h Header) ValidateBasic() error {
	if l := len(h.Signature); l != bls.BLSSignatureSizeInBytes {
		return fmt.Errorf("invalid signature length %v", l)
	}
	return nil
}

func (h Header) GetSignature() (*bls_core.Sign, error) {
	var sign bls_core.Sign
	if err := sign.Deserialize(h.Signature); err != nil {
		return nil, err
	}
	return &sign, nil
}

func (h Header) GetAccountProof() ([][]byte, error) {
	return decodeRLP(h.AccountProof)
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

package types

import (
	"fmt"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

const AccountStorageRootIndex = 2

func VerifyProof(rootHash common.Hash, key []byte, proof [][]byte) ([]byte, error) {
	proofDB := NewMemDB()
	// each node is RLP-serialized
	for _, node := range proof {
		k := crypto.Keccak256(node)
		proofDB.Put(k, node)
	}
	path := crypto.Keccak256(key)

	return trie.VerifyProof(rootHash, path, proofDB)
}

// MemDB is an ethdb.KeyValueReader implementation which is not thread safe and
// assumes that all keys are common.Hash.
type MemDB struct {
	kvs map[common.Hash][]byte
}

// NewMemDB creates a new empty MemDB
func NewMemDB() *MemDB {
	return &MemDB{
		kvs: make(map[common.Hash][]byte),
	}
}

// Has returns true if the MemBD contains the key
func (m *MemDB) Has(key []byte) (bool, error) {
	h := common.BytesToHash(key)
	_, ok := m.kvs[h]
	return ok, nil
}

// Get returns the value of the key, or nil if it's not found
func (m *MemDB) Get(key []byte) ([]byte, error) {
	h := common.BytesToHash(key)
	value, ok := m.kvs[h]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return value, nil
}

// Put sets or updates the value at key
func (m *MemDB) Put(key []byte, value []byte) {
	h := common.BytesToHash(key)
	m.kvs[h] = value
}

// decodeRLP decodes the proof according to the IBFT2.0 client proof format implemented by yui-ibc-solidity
// and formats it for Ethereum's Account/Storage Proof.
func decodeRLP(proof []byte) ([][]byte, error) {
	var val [][][]byte
	if err := rlp.DecodeBytes(proof, &val); err != nil {
		return nil, err
	}

	var res [][]byte
	for _, v := range val {
		bz, err := rlp.EncodeToBytes(v)
		if err != nil {
			return nil, err
		}
		res = append(res, bz)
	}
	return res, nil
}

func extractStorageRootFromAccount(accountRLP []byte) ([]byte, error) {
	var account [][]byte
	if err := rlp.DecodeBytes(accountRLP, &account); err != nil {
		return nil, sdkerrors.Wrap(
			ErrInvalidProof, "failed to decode account")
	}
	if len(account) <= AccountStorageRootIndex {
		return nil, sdkerrors.Wrap(
			ErrInvalidProof, "invalid decoded account")
	}
	return account[AccountStorageRootIndex], nil
}

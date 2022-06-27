package types

import (
	"bytes"
	"errors"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

const AccountStorageRootIndex = 2

// VerifyStorageProof verifies an Ethereum storage proof against the StateRoot.
// It does not verify the account proof against the Ethereum StateHash.
// For absence proof, set nil to `value`.
func VerifyStorageProof(storageHash common.Hash, key, value []byte, proof [][]byte) error {
	var err error
	var valueRlp []byte = nil
	if len(value) != 0 {
		valueRlp, err = rlp.EncodeToBytes(value)
		if err != nil {
			return err
		}
	}
	return Verify(storageHash, key, valueRlp, proof)
}

// Verify verifies that the path generated from key, following the nodes
// in proof leads to a leaf with value, where the hashes are correct up to the
// rootHash.
// WARNING: When the value is not found, `eth_getProof` will return "0x0" at
// the StorageProof `value` field.  In order to verify the proof of non
// existence, you must set `value` to nil, *not* the RLP encoding of 0 or null
// (which would be 0x80).
func Verify(rootHash common.Hash, key []byte, value []byte, proof [][]byte) error {
	res, err := VerifyProof(rootHash, key, proof)
	if err != nil {
		return err
	}
	// absence proof
	if value == nil {
		if res != nil {
			return sdkerrors.Wrapf(ErrInvalidProof,
				"proof did not commit for absence. got: %X. Please ensure proof was submitted with correct proofHeight and to the correct chain.",
				res)
		}
		return nil
	}

	if !bytes.Equal(value, res) {
		return sdkerrors.Wrapf(ErrInvalidProof,
			"proof did not commit to expected value: %X, got: %X. Please ensure proof was submitted with correct proofHeight and to the correct chain.",
			value, res)
	}
	return nil
}

func VerifyProof(rootHash common.Hash, key []byte, proof [][]byte) ([]byte, error) {
	proofDB := NewMemDB()
	// each node is RLP-serialized
	for _, node := range proof {
		k := crypto.Keccak256(node)
		proofDB.Put(k, node)
	}
	path := crypto.Keccak256(key)

	val, _, err := trie.VerifyProof(rootHash, path, proofDB)
	return val, err
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
		return nil, errors.New("key not found")
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

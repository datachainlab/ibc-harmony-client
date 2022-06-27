package types

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
)

// ConstructCommitPayload returns the commit payload for consensus signatures.
// We assume that it is after StakingEpoch.
func ConstructCommitPayload(blockHash common.Hash, blockNum, viewID uint64) []byte {
	blockNumBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(blockNumBytes, blockNum)
	commitPayload := append(blockNumBytes, blockHash.Bytes()...)
	viewIDBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(viewIDBytes, viewID)
	return append(commitPayload, viewIDBytes...)
}

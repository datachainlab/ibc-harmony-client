package types

import (
	"fmt"
)

const (
	// ModuleName defines the Harmony client name
	ModuleName    string = "ibc-harmony"
	HarmonyClient string = "ibc-harmony"

	// KVStore key prefixes for IBC
	KeyEpochStatePrefix string = "epochStates"
)

func EpochStatePath(epoch uint64) string {
	return fmt.Sprintf("%s/%v", KeyEpochStatePrefix, epoch)
}

func EpochStateKey(epoch uint64) []byte {
	return []byte(EpochStatePath(epoch))
}

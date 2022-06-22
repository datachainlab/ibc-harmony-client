package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

var commitmentSlot = big.NewInt(0)

const (
	clientPrefix         = uint8(0)
	consensusStatePrefix = uint8(1)
	connectionPrefix     = uint8(2)
	channelPrefix        = uint8(3)
	packetPrefix         = uint8(4)
	packetAckPrefix      = uint8(5)
)

// Commitment key generator

func ClientCommitmentKey(clientId string) ([]byte, error) {
	return keccak256AbiEncodePacked(clientPrefix, clientId)
}

func ConsensusCommitmentKey(clientId string, height exported.Height) ([]byte, error) {
	return keccak256AbiEncodePacked(consensusStatePrefix, clientId, "/", height)
}

func ConnectionCommitmentKey(connectionId string) ([]byte, error) {
	return keccak256AbiEncodePacked(connectionPrefix, connectionId)
}

func ChannelCommitmentKey(portId, channelId string) ([]byte, error) {
	return keccak256AbiEncodePacked(channelPrefix, portId, "/", channelId)
}

func PacketCommitmentKey(portId, channelId string, sequence uint64) ([]byte, error) {
	return keccak256AbiEncodePacked(packetPrefix, portId, "/", channelId, "/", sequence)
}

func PacketAcknowledgementCommitmentKey(portId, channelId string, sequence uint64) ([]byte, error) {
	return keccak256AbiEncodePacked(packetAckPrefix, portId, "/", channelId, "/", sequence)
}

// Slot calculator

func ClientStateCommitmentSlot(clientId string) ([]byte, error) {
	k, err := ClientCommitmentKey(clientId)
	if err != nil {
		return nil, err
	}
	return keccak256AbiEncodePacked(k, commitmentSlot)
}

func ConsensusStateCommitmentSlot(clientId string, height exported.Height) ([]byte, error) {
	k, err := ConsensusCommitmentKey(clientId, height)
	if err != nil {
		return nil, err
	}
	return keccak256AbiEncodePacked(k, commitmentSlot)
}

func ConnectionCommitmentSlot(connectionId string) ([]byte, error) {
	k, err := ConnectionCommitmentKey(connectionId)
	if err != nil {
		return nil, err
	}
	return keccak256AbiEncodePacked(k, commitmentSlot)
}

func ChannelCommitmentSlot(portId, channelId string) ([]byte, error) {
	k, err := ChannelCommitmentKey(portId, channelId)
	if err != nil {
		return nil, err
	}
	return keccak256AbiEncodePacked(k, commitmentSlot)
}

func PacketCommitmentSlot(portId, channelId string, sequence uint64) ([]byte, error) {
	k, err := PacketCommitmentKey(portId, channelId, sequence)
	if err != nil {
		return nil, err
	}
	return keccak256AbiEncodePacked(k, commitmentSlot)
}

func PacketAcknowledgementCommitmentSlot(portId, channelId string, sequence uint64) ([]byte, error) {
	k, err := PacketAcknowledgementCommitmentKey(portId, channelId, sequence)
	if err != nil {
		return nil, err
	}
	return keccak256AbiEncodePacked(k, commitmentSlot)
}

// keccak256AbiEncodePacked only covers some data types.
func keccak256AbiEncodePacked(data ...interface{}) ([]byte, error) {
	// abi.encodePacked
	var bzs [][]byte
	for _, v := range data {
		var bz []byte
		switch vt := v.(type) {
		case *big.Int:
			bz = math.PaddedBigBytes(math.U256(vt), 32)
		case uint64, uint8:
			b := new(bytes.Buffer)
			if err := binary.Write(b, binary.BigEndian, vt); err != nil {
				return nil, err
			}
			bz = b.Bytes()
		case string:
			// XXX address may be represented by common.Address
			// also, no slot uses an address for now
			if common.IsHexAddress(vt) {
				vt = strings.TrimPrefix(vt, "0x")
				if vt == "" || vt == "0" {
					bz = []byte{0}
					break
				}
				vt = evenLengthHex(vt)
				var err error
				bz, err = hex.DecodeString(vt)
				if err != nil {
					return nil, err
				}
			} else {
				bz = []byte(vt)
			}
		case common.Address:
			bz = vt.Bytes()[:]
		case []byte:
			bz = common.RightPadBytes(vt, len(vt))
		case exported.Height:
			val := big.NewInt(0).Lsh(big.NewInt(0).SetUint64(vt.GetRevisionNumber()), 64)
			val = val.Add(val, big.NewInt(0).SetUint64(vt.GetRevisionHeight()))
			bz = common.LeftPadBytes(val.Bytes(), 16)
		default:
			return nil, fmt.Errorf("unsupported type for abiEncodePacked: %s", reflect.TypeOf(v))
		}
		bzs = append(bzs, bz)
	}

	// keccak256
	return crypto.Keccak256(bzs...), nil
}

func evenLengthHex(v string) string {
	if len(v)%2 == 1 {
		v = "0" + v
	}
	return v
}

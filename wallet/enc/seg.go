package enc

import (
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/vault/shamir"
)

type Hexkey string

func (t Hexkey) Decode() (v []byte) {
	v, err := hex.DecodeString(string(t))
	if err != nil {
		fmt.Println(err)
	}
	return v
}

func Split(secret string, totalShares, threshold int) ([]Hexkey, error) {
	secretBytes := []byte(secret)

	shares, err := shamir.Split(secretBytes, totalShares, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}
	keyShares := make([]Hexkey, 0)
	for _, v := range shares {
		keyShares = append(keyShares, Hexkey(hex.EncodeToString(v)))
	}
	return keyShares, nil
}

func recover(shares []Hexkey) (string, error) {
	var bshares [][]byte
	for _, v := range shares {
		bshares = append(bshares, v.Decode())
	}
	recoveredSecret, err := shamir.Combine(bshares)
	if err != nil {
		return "", fmt.Errorf("failed to recover secret: %w", err)
	}
	return string(recoveredSecret), nil
}

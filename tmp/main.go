package main

import (
	"encoding/hex"
	"fmt"
	"log"

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

func splitKey(secret string, totalShares, threshold int) ([]Hexkey, error) {
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

func recoverKey(shares []Hexkey) (string, error) {
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

func main() {

	secret := "my_secret_seed_value"
	totalShares := 5
	threshold := 3

	// 分片密钥
	shares, err := splitKey(secret, totalShares, threshold)
	if err != nil {
		log.Fatalf("Error splitting key: %v", err)
	}

	fmt.Println("Generated Shares:")
	for i, share := range shares {
		fmt.Printf("Share %d: %s\n", i+1, share)
	}

	selectedShares := shares[:2]
	recoveredSecret, err := recoverKey(selectedShares)
	if err != nil {
		log.Fatalf("Error recovering key: %v", err)
	}

	fmt.Printf("Recovered Secret: %s\n", recoveredSecret)
}

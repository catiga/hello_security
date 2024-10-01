package wallet

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hellodex/HelloSecurity/wallet/enc"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

type ChainCode string

type WalletObj struct {
	Address string
	Epm     string
	mem     string
	pk      string
}

const (
	ETH    = "ETH"
	SOLANA = "SOLANA"
)

func New(addr, mem, pk string) *WalletObj {
	t := &WalletObj{}
	t.Address = addr
	t.mem = mem
	t.pk = pk
	t.Epm = "AES"
	return t
}

func (t *WalletObj) GetMem() string {
	return t.mem
}
func (t *WalletObj) GetPk() string {
	return t.pk
}

func Generate(chainCode ChainCode) (*WalletObj, error) {
	if chainCode == ETH {
		addr, mem, pk, err := generateEVM()
		if err != nil {
			return nil, err
		}

		return New(addr, mem, pk), nil
	}
	return nil, errors.New("unsupport chain")
}

func generateEVM() (string, string, string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", "", "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", "", "", err
	}
	seed := bip39.NewSeed(mnemonic, "")
	privateKey, err := crypto.ToECDSA(pbkdf2.Key(seed, []byte("ethereum"), 2048, 32, sha256.New))
	if err != nil {
		return "", "", "", err
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)

	privateKeyStr := common.Bytes2Hex(privateKeyBytes)
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", "", errors.New("error casting public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println("Public Key:", common.Bytes2Hex(publicKeyBytes))

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	mneBytes, err := enc.Porter().Encrypt([]byte(mnemonic))
	if err != nil {
		return "", "", "", err
	}
	pkBytes, _ := enc.Porter().Encrypt([]byte(privateKeyStr))

	return address, base64.StdEncoding.EncodeToString(mneBytes), base64.StdEncoding.EncodeToString(pkBytes), nil
}

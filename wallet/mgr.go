package wallet

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hellodex/HelloSecurity/wallet/enc"
	"github.com/mr-tron/base58"
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
	ETH    ChainCode = "ETH"
	SOLANA ChainCode = "SOLANA"
)

var suppChains []ChainCode = []ChainCode{ETH, SOLANA}

func isSupp(cc ChainCode) (bool, bool) {
	for _, v := range suppChains {
		evm := true
		if cc == v {
			if cc == SOLANA {
				evm = false
			}
			return true, evm
		}
	}
	return false, false
}

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
	if supp, evm := isSupp(chainCode); supp {
		var addr, mem, pk string
		var err error
		if evm {
			addr, mem, pk, err = generateEVM()
			if err != nil {
				return nil, err
			}
		} else {
			if chainCode == SOLANA {
				addr, mem, pk, err = generateSolana()
				if err != nil {
					return nil, err
				}
			}
		}
		if len(addr) == 0 {
			return nil, errors.New("unknown error for creating wallet")
		}
		return New(addr, mem, pk), nil
	}
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

func generateSolana() (string, string, string, error) {
	// 生成 128-bit 的随机熵
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", "", "", err
	}

	// 通过熵生成助记词
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", "", "", err
	}

	// 生成助记词种子
	seed := bip39.NewSeed(mnemonic, "")

	// 使用PBKDF2生成私钥 (32字节)
	privateKeySeed := pbkdf2.Key(seed, []byte("ed25519 seed"), 2048, ed25519.SeedSize, sha256.New)

	// 根据私钥种子生成 ed25519 私钥
	privateKey := ed25519.NewKeyFromSeed(privateKeySeed)

	// 从私钥生成公钥
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Solana 地址是公钥的 Base58 编码
	address := base58.Encode(publicKey)

	// 将私钥和助记词加密存储
	// 这里加密逻辑可根据需求实现，也可以替换为自己的加密方法
	mneBytes, err := enc.Porter().Encrypt([]byte(mnemonic))
	if err != nil {
		return "", "", "", err
	}

	pkBytes, err := enc.Porter().Encrypt([]byte(base64.StdEncoding.EncodeToString(privateKey)))
	if err != nil {
		return "", "", "", err
	}

	// 返回Solana地址，和加密后的助记词、私钥
	return address, base64.StdEncoding.EncodeToString(mneBytes), base64.StdEncoding.EncodeToString(pkBytes), nil
}

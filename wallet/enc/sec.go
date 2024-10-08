package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"

	log "github.com/hellodex/HelloSecurity/log"
	"github.com/hellodex/HelloSecurity/model"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/pbkdf2"
)

const (
	method      = "AES"
	defaultSeed = "my_secret_seed_value"
)

type EncPort struct {
	aesKey []byte
	Method string
	nonce  uint
}

var e *EncPort

func GetEP() *EncPort {
	return e
}

func init() {
	if e == nil {
		e = &EncPort{
			Method: method,
		}
		// seed := defaultSeed
		// key := sha256.Sum256([]byte(seed))
		// e.aesKey = key[:]
	}
}

func Porter() *EncPort {
	return e
}

func (e *EncPort) SetAESKey(seed string) error {
	if len(e.aesKey) > 0 {
		return errors.New("can not reset keys")
	}
	aesKeyBytes := sha256.Sum256([]byte(seed))

	e.aesKey = aesKeyBytes[:]

	block, err := aes.NewCipher(e.aesKey)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if aesGCM.NonceSize() == 0 {
		return errors.New("invalid key set")
	}
	e.nonce = uint(aesGCM.NonceSize())
	return nil
}

func (e *EncPort) GetNonce() uint {
	return e.nonce
}

func (e *EncPort) Encrypt(plaintext []byte) ([]byte, error) {
	if len(e.aesKey) == 0 {
		return nil, errors.New("AES key not set")
	}

	block, err := aes.NewCipher(e.aesKey)
	if err != nil {
		return nil, err
	}

	// 使用 GCM 模式
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (e *EncPort) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	if len(e.aesKey) == 0 {
		return nil, errors.New("AES key not set")
	}

	block, err := aes.NewCipher(e.aesKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (e *EncPort) SigEth(wg *model.WalletGenerated, content []byte) ([]byte, error) {
	encryptedPrivKey := wg.EncryptPK
	nonceSize := wg.Nonce
	encryptedPrivKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedPrivKey)
	nonce := encryptedPrivKeyBytes[:nonceSize]
	ciphertext := encryptedPrivKeyBytes[nonceSize:]

	decryptedPrivKeyBytes, err := e.decrypt(ciphertext, nonce)
	if err != nil {
		return nil, err
	}
	var _32pk []byte

	_32pk, err = hex.DecodeString(string(decryptedPrivKeyBytes))
	if err != nil {
		return nil, err
	}
	if len(_32pk) != 32 {
		return nil, errors.New("pk length padding error")
	}

	privateKey, err := crypto.ToECDSA(_32pk)
	if err != nil {
		return nil, err
	}

	hash := crypto.Keccak256([]byte(content))

	sig, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (e *EncPort) SigSol(wg *model.WalletGenerated, content []byte) ([]byte, error) {
	encryptedPrivKey := wg.EncryptPK
	nonceSize := wg.Nonce
	encryptedPrivKeyBytes, err := base64.StdEncoding.DecodeString(encryptedPrivKey)
	if err != nil {
		return nil, err
	}

	nonce := encryptedPrivKeyBytes[:nonceSize]
	ciphertext := encryptedPrivKeyBytes[nonceSize:]

	decryptedPrivKeyBytes, err := e.decrypt(ciphertext, nonce)
	if err != nil {
		return nil, err
	}

	realPk, _ := base64.StdEncoding.DecodeString(string(decryptedPrivKeyBytes))

	privKey := ed25519.PrivateKey(realPk)

	sig := ed25519.Sign(privKey, content)

	return sig, nil
}

func (e *EncPort) SigEvmTx(wg *model.WalletGenerated, tx *types.Transaction, chainId *big.Int) (*types.Transaction, error) {
	encryptedPrivKey := wg.EncryptPK
	nonceSize := wg.Nonce

	encryptedPrivKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedPrivKey)
	nonce := encryptedPrivKeyBytes[:nonceSize]
	ciphertext := encryptedPrivKeyBytes[nonceSize:]

	decryptedPrivKeyBytes, err := e.decrypt(ciphertext, nonce)
	if err != nil {
		return nil, err
	}
	var _32pk []byte

	_32pk, err = hex.DecodeString(string(decryptedPrivKeyBytes))
	if err != nil {
		return nil, err
	}
	if len(_32pk) != 32 {
		return nil, errors.New("pk length padding error")
	}

	privateKey, err := crypto.ToECDSA(_32pk)
	if err != nil {
		return nil, err
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), privateKey)

	return signedTx, err
}

func NewKeyStories() (string, error) {
	var mnemonic string
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		log.Error("NewKeyStories error :", err)
		return "", err
	}
	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		log.Error("NewKeyStories error :", err)
		return "", err
	}
	mbytes, err := Porter().Encrypt([]byte(mnemonic))
	if err != nil {
		log.Error("NewKeyStories error :", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(mbytes), nil
}

func GenerateEVM(wg *model.WalletGroup) (string, string, string, error) {
	var pkBytes, mneBytes []byte
	var address, mnemonic string
	if wg == nil {
		entropy, err := bip39.NewEntropy(128)
		if err != nil {
			return "", "", "", err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return "", "", "", err
		}

	} else {
		encryptedPrivKeyBytes, _ := base64.StdEncoding.DecodeString(wg.EncryptMem)
		nonce := encryptedPrivKeyBytes[:wg.Nonce]
		ciphertext := encryptedPrivKeyBytes[wg.Nonce:]

		decryptMno, err := Porter().decrypt(ciphertext, nonce)
		if err != nil {
			return "", "", "", err
		}
		mnemonic = string(decryptMno)
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

	address = crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	mneBytes, err = Porter().Encrypt([]byte(mnemonic))
	if err != nil {
		return "", "", "", err
	}
	pkBytes, _ = Porter().Encrypt([]byte(privateKeyStr))

	return address, base64.StdEncoding.EncodeToString(mneBytes), base64.StdEncoding.EncodeToString(pkBytes), nil
}

func GenerateSolana(wg *model.WalletGroup) (string, string, string, error) {
	var pkBytes, mneBytes []byte
	var address, mnemonic string
	if wg == nil {
		entropy, err := bip39.NewEntropy(128)
		if err != nil {
			return "", "", "", err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return "", "", "", err
		}

	} else {
		encryptedPrivKeyBytes, _ := base64.StdEncoding.DecodeString(wg.EncryptMem)
		nonce := encryptedPrivKeyBytes[:wg.Nonce]
		ciphertext := encryptedPrivKeyBytes[wg.Nonce:]

		decryptMno, err := Porter().decrypt(ciphertext, nonce)
		if err != nil {
			return "", "", "", err
		}
		mnemonic = string(decryptMno)
	}

	seed := bip39.NewSeed(mnemonic, "")

	privateKeySeed := pbkdf2.Key(seed, []byte("ed25519 seed"), 2048, ed25519.SeedSize, sha256.New)

	privateKey := ed25519.NewKeyFromSeed(privateKeySeed)

	publicKey := privateKey.Public().(ed25519.PublicKey)

	address = base58.Encode(publicKey)

	mneBytes, err := Porter().Encrypt([]byte(mnemonic))
	if err != nil {
		return "", "", "", err
	}

	pkBytes, err = Porter().Encrypt([]byte(base64.StdEncoding.EncodeToString(privateKey)))
	if err != nil {
		return "", "", "", err
	}

	return address, base64.StdEncoding.EncodeToString(mneBytes), base64.StdEncoding.EncodeToString(pkBytes), nil
}

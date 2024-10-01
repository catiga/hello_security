package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"golang.org/x/crypto/ed25519"
)

const (
	method      = "AES"
	defaultSeed = "my_secret_seed_value"
)

type EncPort struct {
	aesKey []byte
	Method string
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
	aesKeyBytes := sha256.Sum256([]byte(seed))

	e.aesKey = aesKeyBytes[:]
	return nil
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

func (e *EncPort) SigEth(encryptedPrivKey string, content []byte) ([]byte, error) {
	encryptedPrivKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedPrivKey)
	nonce := encryptedPrivKeyBytes[:12]
	ciphertext := encryptedPrivKeyBytes[12:]

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

func (e *EncPort) SigSol(encryptedPrivKey string, content []byte) ([]byte, error) {
	encryptedPrivKeyBytes, err := base64.StdEncoding.DecodeString(encryptedPrivKey)
	if err != nil {
		return nil, err
	}

	nonce := encryptedPrivKeyBytes[:12]
	ciphertext := encryptedPrivKeyBytes[12:]

	decryptedPrivKeyBytes, err := e.decrypt(ciphertext, nonce)
	if err != nil {
		return nil, err
	}

	privKey := ed25519.PrivateKey(decryptedPrivKeyBytes)

	sig := ed25519.Sign(privKey, content)

	return sig, nil
}

func (e *EncPort) SigEvmTx(encryptedPrivKey string, tx *types.Transaction, chainId *big.Int) (*types.Transaction, error) {
	encryptedPrivKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedPrivKey)
	nonce := encryptedPrivKeyBytes[:12]
	ciphertext := encryptedPrivKeyBytes[12:]

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

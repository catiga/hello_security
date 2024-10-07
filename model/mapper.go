package model

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/hellodex/HelloSecurity/codes"
)

type WalletGenerated struct {
	ID             uint64    `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	UserID         string    `gorm:"column:user_id" json:"user_id"`
	Wallet         string    `gorm:"column:wallet" json:"wallet"`
	ChainCode      string    `gorm:"column:chain_code" json:"chain_code"`
	EncryptPK      string    `gorm:"column:encrypt_pk" json:"encrypt_pk"`
	EncryptVersion string    `gorm:"column:encrypt_version" json:"encrypt_version"`
	CreateTime     time.Time `gorm:"column:create_time" json:"create_time"`
	Channel        string    `gorm:"column:channel" json:"channel"`
	CanPort        bool      `gorm:"column:canport" json:"canport"`
	Status         string    `gorm:"column:status" json:"status"`
	GroupID        uint64    `gorm:"column:group_id" json:"group_id"`
	Nonce          int       `gorm:"column:nonce" json:"nonce"`
}

// TableName sets the insert table name for this struct type
func (WalletGenerated) TableName() string {
	return "wallet_generated"
}

type WalletGroup struct {
	ID             uint64    `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	UserID         string    `gorm:"column:user_id" json:"user_id"`
	CreateTime     time.Time `gorm:"column:create_time" json:"create_time"`
	EncryptMem     string    `gorm:"column:encrypt_mem" json:"encrypt_mem"`
	EncryptVersion string    `gorm:"column:encrypt_version" json:"encrypt_version"`
	Nonce          int       `gorm:"column:nonce" json:"nonce"`
}

func (WalletGroup) TableName() string {
	return "wallet_group"
}

type WalletLog struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	WalletID  int64     `gorm:"column:wallet_id" json:"wallet_id"`
	Wallet    string    `gorm:"column:wallet" json:"wallet"`
	Data      string    `gorm:"column:data" json:"data"`
	Sig       string    `gorm:"column:sig" json:"sig"`
	ChainCode string    `gorm:"column:chain_code" json:"chain_code"`
	TxHash    string    `gorm:"column:tx_hash" json:"tx_hash"`
	OpTime    time.Time `gorm:"column:op_time" json:"op_time"`
	Operation string    `gorm:"column:operation" json:"operation"`
	Err       string    `gorm:"column:error" json:"error"`
}

func (WalletLog) TableName() string {
	return "wallet_log"
}

type SysChannel struct {
	ID         uint64    `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AppID      string    `gorm:"column:app_id" json:"app_id"`
	AppKey     string    `gorm:"column:app_key;size:100" json:"app_key"`
	Status     string    `gorm:"column:status" json:"status"`
	SigMethod  string    `gorm:"column:sig_method;size:255" json:"sig_method"`
	CreateTime time.Time `gorm:"column:create_time" json:"create_time"`
	UpdateTime time.Time `gorm:"column:update_time" json:"update_time"`
}

func (SysChannel) TableName() string {
	return "sys_channel"
}

func (t *SysChannel) Verify(data, sig string) (bool, int) {
	if t.SigMethod != "SHA256" {
		return false, codes.CODE_ERR_SIGMETHOD_UNSUPP
	}
	if len(data) == 0 || len(sig) == 0 {
		return false, codes.CODE_ERR_AUTHTOKEN_FAIL
	}
	data = fmt.Sprintf("%s%s", data, t.AppKey)

	hashByte := sha256.Sum256([]byte(data))
	hash := fmt.Sprintf("%x", hashByte[:])
	if hash != sig {
		return false, codes.CODE_ERR_AUTHTOKEN_FAIL
	}
	return true, codes.CODE_SUCCESS
}

type SysDes struct {
	ID         int64     `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	Desk       string    `gorm:"column:desk" json:"desk"`
	Desv       string    `gorm:"column:desv; json:"desv"`
	UpdateTime time.Time `gorm:"column:update_time" json:"update_time"`
	Flag       int       `gorm:"column:flag; json:"flag"`
}

func (SysDes) TableName() string {
	return "sys_des"
}

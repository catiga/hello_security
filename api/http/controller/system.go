package controller

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/hellodex/HelloSecurity/api/common"
	"github.com/hellodex/HelloSecurity/codes"
	"github.com/hellodex/HelloSecurity/config"
	"github.com/hellodex/HelloSecurity/log"
	"github.com/hellodex/HelloSecurity/model"
	"github.com/hellodex/HelloSecurity/system"
	"github.com/hellodex/HelloSecurity/wallet"

	"github.com/gin-gonic/gin"
)

type CreateWalletRequest struct {
	UserID    string `json:"user_id"`
	ChainCode string `json:"chain_code"`
}

type SigWalletRequest struct {
	Message  string `json:"message"`
	Type     string `json:"type"`
	WalletID uint64 `json:"wallet_id"`
	To       string `json:"to"`
}

func CreateWallet(c *gin.Context) {
	var req CreateWalletRequest
	res := common.Response{}
	res.Timestamp = time.Now().Unix()

	if err := c.ShouldBindJSON(&req); err != nil {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "Invalid request"
		c.JSON(http.StatusBadRequest, res)
		return
	}

	db := system.GetDb()
	var wg model.WalletGenerated
	db.Model(&model.WalletGenerated{}).Where("user_id = ? and chain_code = ? and status = ?", req.UserID, req.ChainCode, "00").First(&wg)
	if wg.ID > 0 {
		res.Code = codes.CODE_ERR_EXIST_OBJ
		res.Msg = "exist wallet for this chain code"
		c.JSON(http.StatusBadRequest, res)
		return
	}

	wal, err := wallet.Generate(wallet.ChainCode(req.ChainCode))
	if err != nil {
		res.Code = codes.CODE_ERR_UNKNOWN
		res.Msg = err.Error()
		c.JSON(http.StatusBadRequest, res)
		return
	}

	channel, _ := c.Get("APP_ID")
	wg = model.WalletGenerated{
		UserID:         req.UserID,
		ChainCode:      req.ChainCode,
		Wallet:         wal.Address,
		EncryptPK:      wal.GetPk(),
		EncryptMem:     wal.GetMem(),
		EncryptVersion: wal.Epm,
		CreateTime:     time.Now(),
		Channel:        fmt.Sprintf("%v", channel),
		CanPort:        false,
		Status:         "00",
	}

	err = db.Model(&model.WalletGenerated{}).Save(&wg).Error
	if err != nil {
		log.Errorf("create wallet error ", err)
	}

	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = struct {
		WalletAddr string `json:"wallet_addr"`
		WalletId   uint64 `json:"wallet_id"`
	}{
		WalletAddr: wg.Wallet,
		WalletId:   uint64(wg.ID),
	}

	c.JSON(http.StatusOK, res)
}

func Sig(c *gin.Context) {
	var req SigWalletRequest
	res := common.Response{}
	res.Timestamp = time.Now().Unix()

	if err := c.ShouldBindJSON(&req); err != nil {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "Invalid request"
		c.JSON(http.StatusBadRequest, res)
		return
	}

	if len(req.Message) == 0 || (req.Type != "transaction" && req.Type != "sign") {
		res.Code = codes.CODE_ERR_BAT_PARAMS
		res.Msg = "bad request parameters"
		c.JSON(http.StatusBadRequest, res)
		return
	}

	db := system.GetDb()
	var wg model.WalletGenerated
	db.Model(&model.WalletGenerated{}).Where("id = ? and status = ?", req.WalletID, "00").First(&wg)
	if wg.ID == 0 {
		res.Code = codes.CODES_ERR_OBJ_NOT_FOUND
		res.Msg = fmt.Sprintf("unable to find wallet object with %d", req.WalletID)
		c.JSON(http.StatusBadRequest, res)
		return
	}

	messageContent, _ := base64.StdEncoding.DecodeString(req.Message)
	// result, err := enc.Porter().Sig(wg.EncryptPK, messageContent)
	// if err != nil {
	// 	res.Code = codes.CODES_ERR_SIG_COMMON
	// 	res.Msg = fmt.Sprintf("sign error %s", err.Error())
	// 	c.JSON(http.StatusBadRequest, res)
	// 	return
	// }

	// sigStr := base64.StdEncoding.EncodeToString(result)

	chainConfig := config.GetRpcConfig(wg.ChainCode)
	txhash, sig, error := chainConfig.HandleMessage(messageContent, req.To, req.Type, &wg)
	sigStr := ""
	if len(sig) > 0 {
		sigStr = base64.StdEncoding.EncodeToString(sig)
	}

	wl := &model.WalletLog{
		WalletID:  int64(req.WalletID),
		Wallet:    wg.Wallet,
		Data:      req.Message,
		Sig:       sigStr,
		ChainCode: wg.ChainCode,
		Operation: req.Type,
		OpTime:    time.Now(),
		TxHash:    txhash,
	}
	if error != nil {
		wl.Err = error.Error()
	}
	err := db.Model(&model.WalletLog{}).Save(wl).Error
	if err != nil {
		log.Error("save log error ", err)
	}

	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = struct {
		Signature string `json:signature"`
		Wallet    string `json:wallet"`
		Tx        string `json:"tx"`
	}{
		Signature: sigStr,
		Wallet:    wg.Wallet,
		Tx:        "",
	}
	c.JSON(http.StatusOK, res)
}

func List(c *gin.Context) {
	var req CreateWalletRequest
	res := common.Response{}
	res.Timestamp = time.Now().Unix()

	if err := c.ShouldBindJSON(&req); err != nil {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "Invalid request"
		c.JSON(http.StatusBadRequest, res)
		return
	}

	db := system.GetDb()
	var wg []model.WalletGenerated
	db.Model(&model.WalletGenerated{}).Where("user_id = ? and status = ?", req.UserID, "00").Find(&wg)

	type WalletList struct {
		ID         uint64    `json:"id"`
		Wallet     string    `json:"wallet"`
		Chain      string    `json:"chain"`
		CreateTime time.Time `json:"create_time"`
		Export     bool      `json:"export"`
	}

	retData := make([]WalletList, 0)
	for _, v := range wg {
		retData = append(retData, WalletList{
			ID:         uint64(v.ID),
			Wallet:     v.Wallet,
			Chain:      v.ChainCode,
			CreateTime: v.CreateTime,
			Export:     v.CanPort,
		})
	}

	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = retData
	c.JSON(http.StatusOK, res)
}

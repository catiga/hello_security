package controller

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/hellodex/HelloSecurity/api/common"
	chain "github.com/hellodex/HelloSecurity/chain"
	"github.com/hellodex/HelloSecurity/codes"
	"github.com/hellodex/HelloSecurity/config"
	"github.com/hellodex/HelloSecurity/log"
	"github.com/hellodex/HelloSecurity/model"
	"github.com/hellodex/HelloSecurity/system"
	"github.com/hellodex/HelloSecurity/wallet"
	"github.com/hellodex/HelloSecurity/wallet/enc"

	"github.com/gin-gonic/gin"
)

type CreateWalletRequest struct {
	UserID    string `json:"user_id"`
	ChainCode string `json:"chain_code"`
	GroupID   int    `json:"group_id"`
	Nop       string `json:"nop"`
}

type SigWalletRequest struct {
	Message  string          `json:"message"`
	Type     string          `json:"type"`
	WalletID uint64          `json:"wallet_id"`
	To       string          `json:"to"`
	Amount   *big.Int        `json:"amount"`
	Config   common.OpConfig `json:"config"`
}

type CreateBatchWalletRequest struct {
	UserID     string   `json:"user_id"`
	ChainCodes []string `json:"chain_codes"`
	GroupID    int      `json:"group_id"`
	Nop        string   `json:"nop"`
}

func CreateWallet(c *gin.Context) {
	var req CreateWalletRequest
	res := common.Response{}
	res.Timestamp = time.Now().Unix()

	if err := c.ShouldBindJSON(&req); err != nil {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "Invalid request"
		c.JSON(http.StatusOK, res)
		return
	}

	db := system.GetDb()
	var walletGroup *model.WalletGroup
	var walletGroups []model.WalletGroup
	err := db.Model(&model.WalletGroup{}).Where("user_id = ?", req.UserID).Find(&walletGroups).Error

	if req.GroupID > 0 {
		for _, v := range walletGroups {
			if v.ID == uint64(req.GroupID) {
				walletGroup = &v
			}
		}
		if err != nil {
			res.Code = codes.CODE_ERR_UNKNOWN
			res.Msg = err.Error()
			c.JSON(http.StatusOK, res)
			return
		}
		if walletGroup == nil {
			res.Code = codes.CODES_ERR_OBJ_NOT_FOUND
			res.Msg = fmt.Sprintf("can not find by group id:%d", req.GroupID)
			c.JSON(http.StatusOK, res)
			return
		}
	} else {
		if req.Nop == "Y" || len(walletGroups) == 0 {
			strmneno, err := enc.NewKeyStories()
			if err != nil {
				res.Code = codes.CODE_ERR_UNKNOWN
				res.Msg = fmt.Sprintf("can not create wallet group : %s", err.Error())
				c.JSON(http.StatusOK, res)
				return
			}
			walletGroup = &model.WalletGroup{
				UserID:         req.UserID,
				CreateTime:     time.Now(),
				EncryptMem:     strmneno,
				EncryptVersion: fmt.Sprintf("AES:%d", 1),
				Nonce:          int(enc.Porter().GetNonce()),
			}
			db.Save(walletGroup)
		} else {
			walletGroup = &walletGroups[0]
		}
	}

	var wgs []model.WalletGenerated
	db.Model(&model.WalletGenerated{}).Where("user_id = ? and group_id = ? and status = ?", req.UserID, walletGroup.ID, "00").Find(&wgs)

	var exist *model.WalletGenerated
	for _, v := range wgs {
		if v.ChainCode == req.ChainCode {
			exist = &v
		}
	}
	if exist != nil {
		res.Code = codes.CODE_ERR_EXIST_OBJ
		res.Msg = "exist wallet for this chain code"
		c.JSON(http.StatusOK, res)
		return
	}
	// var encmno string = walletGroup.EncryptMem

	wal, err := wallet.Generate(walletGroup, wallet.ChainCode(req.ChainCode))
	if err != nil {
		res.Code = codes.CODE_ERR_UNKNOWN
		res.Msg = err.Error()
		c.JSON(http.StatusOK, res)
		return
	}

	channel, _ := c.Get("APP_ID")
	wg := model.WalletGenerated{
		UserID:         req.UserID,
		ChainCode:      req.ChainCode,
		Wallet:         wal.Address,
		EncryptPK:      wal.GetPk(),
		EncryptVersion: wal.Epm,
		CreateTime:     time.Now(),
		Channel:        fmt.Sprintf("%v", channel),
		CanPort:        false,
		Status:         "00",
		GroupID:        walletGroup.ID,
		Nonce:          walletGroup.Nonce,
	}

	err = db.Model(&model.WalletGenerated{}).Save(&wg).Error
	if err != nil {
		log.Errorf("create wallet error %v", err)
	}

	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = struct {
		WalletAddr string `json:"wallet_addr"`
		WalletId   uint64 `json:"wallet_id"`
		GroupID    uint64 `json:"group_id"`
	}{
		WalletAddr: wg.Wallet,
		WalletId:   wg.ID,
		GroupID:    walletGroup.ID,
	}

	c.JSON(http.StatusOK, res)
}

func CreateBatchWallet(c *gin.Context) {
	var req CreateBatchWalletRequest
	res := common.Response{}
	res.Timestamp = time.Now().Unix()

	if err := c.ShouldBindJSON(&req); err != nil {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "Invalid request"
		c.JSON(http.StatusOK, res)
		return
	}

	if len(req.ChainCodes) == 0 {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "chain list empty"
		c.JSON(http.StatusOK, res)
		return
	}
	validChains := wallet.CheckAllCodes(req.ChainCodes)
	if len(validChains) == 0 {
		res.Code = codes.CODE_ERR_BAT_PARAMS
		res.Msg = "chain list all invalid"
		c.JSON(http.StatusOK, res)
		return
	}

	db := system.GetDb()
	var walletGroup *model.WalletGroup
	var walletGroups []model.WalletGroup
	err := db.Model(&model.WalletGroup{}).Where("user_id = ?", req.UserID).Find(&walletGroups).Error

	if req.GroupID > 0 {
		for _, v := range walletGroups {
			if v.ID == uint64(req.GroupID) {
				walletGroup = &v
			}
		}
		if err != nil {
			res.Code = codes.CODE_ERR_UNKNOWN
			res.Msg = err.Error()
			c.JSON(http.StatusOK, res)
			return
		}
		if walletGroup == nil {
			res.Code = codes.CODES_ERR_OBJ_NOT_FOUND
			res.Msg = fmt.Sprintf("can not find by group id:%d", req.GroupID)
			c.JSON(http.StatusOK, res)
			return
		}
	} else {
		if req.Nop == "Y" || len(walletGroups) == 0 {
			strmneno, err := enc.NewKeyStories()
			if err != nil {
				res.Code = codes.CODE_ERR_UNKNOWN
				res.Msg = fmt.Sprintf("can not create wallet group : %s", err.Error())
				c.JSON(http.StatusOK, res)
				return
			}
			walletGroup = &model.WalletGroup{
				UserID:         req.UserID,
				CreateTime:     time.Now(),
				EncryptMem:     strmneno,
				EncryptVersion: fmt.Sprintf("AES:%d", 1),
				Nonce:          int(enc.Porter().GetNonce()),
			}
			db.Save(walletGroup)
		} else {
			walletGroup = &walletGroups[0]
		}
	}

	var wgs []model.WalletGenerated
	db.Model(&model.WalletGenerated{}).
		Where("user_id = ? and group_id = ? and status = ? and chain_code IN ?", req.UserID, walletGroup.ID, "00", validChains).Find(&wgs)

	needCreates := make([]string, 0)
	for _, v := range validChains {
		exist := false
		for _, w := range wgs {
			if v == w.ChainCode {
				exist = true
				break
			}
		}
		if !exist {
			needCreates = append(needCreates, v)
		}
	}
	log.Info("need create: ", needCreates)
	type GetBackWallet struct {
		WalletAddr string `json:"wallet_addr"`
		WalletId   uint64 `json:"wallet_id"`
		GroupID    uint64 `json:"group_id"`
		ChainCode  string `json:"chain_code"`
	}
	if len(needCreates) == 0 {
		resultList := make([]GetBackWallet, 0)
		for _, w := range wgs {
			resultList = append(resultList, GetBackWallet{
				WalletAddr: w.Wallet,
				WalletId:   w.ID,
				GroupID:    w.GroupID,
				ChainCode:  w.ChainCode,
			})
		}
		res.Code = codes.CODE_SUCCESS
		res.Msg = "success"
		res.Data = resultList

		c.JSON(http.StatusOK, res)
		return
	}

	// newWgs := make([]model.WalletGenerated, 0)
	for _, v := range needCreates {
		wal, err := wallet.Generate(walletGroup, wallet.ChainCode(v))
		if err != nil {
			res.Code = codes.CODE_ERR_UNKNOWN
			res.Msg = err.Error()
			c.JSON(http.StatusOK, res)
			return
		}

		channel, _ := c.Get("APP_ID")
		wg := model.WalletGenerated{
			UserID:         req.UserID,
			ChainCode:      v,
			Wallet:         wal.Address,
			EncryptPK:      wal.GetPk(),
			EncryptVersion: wal.Epm,
			CreateTime:     time.Now(),
			Channel:        fmt.Sprintf("%v", channel),
			CanPort:        false,
			Status:         "00",
			GroupID:        walletGroup.ID,
			Nonce:          walletGroup.Nonce,
		}

		err = db.Model(&model.WalletGenerated{}).Save(&wg).Error
		if err != nil {
			log.Errorf("create wallet error %v", err)
		} else {
			wgs = append(wgs, wg)
		}
	}

	resultList := make([]GetBackWallet, 0)
	for _, w := range wgs {
		resultList = append(resultList, GetBackWallet{
			WalletAddr: w.Wallet,
			WalletId:   w.ID,
			GroupID:    w.GroupID,
			ChainCode:  w.ChainCode,
		})
	}
	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = resultList

	c.JSON(http.StatusOK, res)
}

func Sig(c *gin.Context) {
	var req SigWalletRequest
	res := common.Response{}
	res.Timestamp = time.Now().Unix()

	if err := c.ShouldBindJSON(&req); err != nil {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "Invalid request"
		c.JSON(http.StatusOK, res)
		return
	}

	if len(req.Message) == 0 || (req.Type != "transaction" && req.Type != "sign") {
		res.Code = codes.CODE_ERR_BAT_PARAMS
		res.Msg = "bad request parameters"
		c.JSON(http.StatusOK, res)
		return
	}

	db := system.GetDb()
	var wg model.WalletGenerated
	db.Model(&model.WalletGenerated{}).Where("id = ? and status = ?", req.WalletID, "00").First(&wg)
	if wg.ID == 0 {
		res.Code = codes.CODES_ERR_OBJ_NOT_FOUND
		res.Msg = fmt.Sprintf("unable to find wallet object with %d", req.WalletID)
		c.JSON(http.StatusOK, res)
		return
	}

	log.Info("accept req: ", req.Message)

	chainConfig := config.GetRpcConfig(wg.ChainCode)
	txhash, sig, err := chain.HandleMessage(chainConfig, req.Message, req.To, req.Type, req.Amount, &req.Config, &wg)
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

	if err != nil {
		wl.Err = err.Error()
	}
	err1 := db.Model(&model.WalletLog{}).Save(wl).Error
	if err1 != nil {
		log.Error("save log error ", err)
	}

	if err != nil {
		res.Code = codes.CODES_ERR_TX
		res.Msg = err.Error()
		c.JSON(http.StatusOK, res)
		return
	}

	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = struct {
		Signature string `json:"signature"`
		Wallet    string `json:"wallet"`
		Tx        string `json:"tx"`
	}{
		Signature: sigStr,
		Wallet:    wg.Wallet,
		Tx:        txhash,
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
		GroupID    uint64    `json:"group_id"`
	}

	retData := make([]WalletList, 0)
	for _, v := range wg {
		retData = append(retData, WalletList{
			ID:         uint64(v.ID),
			Wallet:     v.Wallet,
			Chain:      v.ChainCode,
			CreateTime: v.CreateTime,
			Export:     v.CanPort,
			GroupID:    v.GroupID,
		})
	}

	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = retData
	c.JSON(http.StatusOK, res)
}

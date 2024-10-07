package controller

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hellodex/HelloSecurity/api/common"
	"github.com/hellodex/HelloSecurity/codes"
	"github.com/hellodex/HelloSecurity/config"
	"github.com/hellodex/HelloSecurity/log"
	"github.com/hellodex/HelloSecurity/model"
	"github.com/hellodex/HelloSecurity/system"
)

type TokenTransfer struct {
	WalletID uint64   `json:"wallet_id"`
	Token    string   `json:"token"`
	To       string   `json:"to"`
	Amount   *big.Int `json:"amount"`
}

func Transfer(c *gin.Context) {
	var req TokenTransfer
	res := common.Response{}
	res.Timestamp = time.Now().Unix()

	if err := c.ShouldBindJSON(&req); err != nil {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "Invalid request"
		c.JSON(http.StatusBadRequest, res)
		return
	}

	if len(req.To) == 0 {
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

	// if wg.ChainCode != "SOLANA" {
	// 	res.Code = codes.CODE_ERR_METHOD_UNSUPPORT
	// 	res.Msg = fmt.Sprintf("support solana for now %d", req.WalletID)
	// 	c.JSON(http.StatusBadRequest, res)
	// 	return
	// }

	chainConfig := config.GetRpcConfig(wg.ChainCode)

	txhash, err := chainConfig.HandlTransfer(req.To, req.Token, req.Amount, &wg)

	if err != nil {
		log.Error("transfer error:", req, err)
		res.Code = codes.CODE_ERR_UNKNOWN
		res.Msg = fmt.Sprintf("unknown error %s", err.Error())
		c.JSON(http.StatusBadRequest, res)
		return
	}

	reqdata, _ := json.Marshal(req)

	wl := &model.WalletLog{
		WalletID:  int64(req.WalletID),
		Wallet:    wg.Wallet,
		Data:      string(reqdata),
		ChainCode: wg.ChainCode,
		Operation: "transfer",
		OpTime:    time.Now(),
		TxHash:    txhash,
	}

	err = db.Model(&model.WalletLog{}).Save(wl).Error
	if err != nil {
		log.Error("save log error ", err)
	}

	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = struct {
		Wallet string `json:"wallet"`
		Tx     string `json:"tx"`
	}{
		Wallet: wg.Wallet,
		Tx:     txhash,
	}
	c.JSON(http.StatusOK, res)
}

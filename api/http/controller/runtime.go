package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hellodex/HelloSecurity/api/common"
	"github.com/hellodex/HelloSecurity/codes"
)

type KeyInitReq struct {
	Val string `json:"val"`
}

func InitKeySeg(c *gin.Context) {
	var req KeyInitReq
	res := common.Response{}
	res.Timestamp = time.Now().Unix()

	if err := c.ShouldBindJSON(&req); err != nil {
		res.Code = codes.CODE_ERR_REQFORMAT
		res.Msg = "Invalid Request"
		c.JSON(http.StatusBadRequest, res)
		return
	}

	if len(req.Val) == 0 {
		res.Code = codes.CODES_ERR_PARA_EMPTY
		res.Msg = "Invalid Parameter"
		c.JSON(http.StatusBadRequest, res)
		return
	}

	res.Code = codes.CODE_SUCCESS
	res.Msg = "success"
	res.Data = ""

	c.JSON(http.StatusOK, res)
}

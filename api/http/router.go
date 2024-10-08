package http

import (
	"github.com/hellodex/HelloSecurity/api/http/controller"

	"github.com/gin-gonic/gin"

	"github.com/hellodex/HelloSecurity/api/interceptor"
)

func Routers(e *gin.RouterGroup) {

	sysGroup := e.Group("/auth", interceptor.HttpInterceptor())
	sysGroup.POST("/wallet/create/byChain", controller.CreateWallet)
	sysGroup.POST("/wallet/create/batch", controller.CreateBatchWallet)
	sysGroup.POST("/wallet/sig", controller.Sig)
	sysGroup.POST("/wallet/list", controller.List)
	sysGroup.POST("/wallet/transfer", controller.Transfer)
}

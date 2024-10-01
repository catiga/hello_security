package config

import (
	"fmt"
	"testing"
)

func TestConfigInit(t *testing.T) {
	rpcList := systemConfig.Chain[0].GetRpc()
	rpcMapList := systemConfig.Chain[0].GetRpcMapper()
	fmt.Println(rpcList, rpcMapList)

	i := systemConfig.Chain[0].RpcMap[rpcList[0]]
	fmt.Println(i)
}

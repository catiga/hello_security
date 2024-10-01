package util

import (
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

func GetSts() string {
	client, err := sts.NewClientWithAccessKey("ap-southeast-1", "", "")

	fmt.Println(client.GetConfig())

	//构建请求对象。
	request := sts.CreateAssumeRoleRequest()
	request.Scheme = "https"
	// request.Method = "GET"

	//设置参数。关于参数含义和设置方法，请参见《API参考》。
	request.RoleArn = ""
	request.RoleSessionName = ""
	request.DurationSeconds = requests.NewInteger(3600)

	//发起请求，并得到响应。
	response, err := client.AssumeRole(request)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	// response.
	fmt.Printf("response is %#v\n", response.GetHttpContentString())

	return response.GetHttpContentString()

}

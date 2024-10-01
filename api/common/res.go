package common

type Response struct {
	Code      int64       `json:"code"`
	Msg       string      `json:"msg"`
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"data"`
}

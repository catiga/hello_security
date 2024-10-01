package enc

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/mr-tron/base58"
)

func TestSec(t *testing.T) {
	s := "test helloworld"
	bs, _ := base58.Decode(s)
	bss, err := Porter().Encrypt(bs)

	result := base64.StdEncoding.EncodeToString(bss)
	fmt.Println(result, err)
}

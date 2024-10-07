package enc

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/mr-tron/base58"
)

func TestSec(t *testing.T) {
	s := "5GhfLYDExhaBTaWpwbfTk6DrMYdv8vkiFLwgdbz2vouzxe2dxy6RNGB13ozz9ns7RjLZoLHMGJK5jZtFJpxYhzWn"
	bs := []byte(s)
	e := Porter()
	e.SetAESKey("my_secret_seed_value")
	bss, _ := e.Encrypt(bs)

	nonce := e.GetNonce()

	bsss, err := e.decrypt(bss[nonce:], bss[:nonce])
	bssss := string(bsss)

	result := base58.Encode(bss)
	fmt.Println(result, err, bssss)

	vs := "QdYipjM+H/NiQxG4yXg1azMms7cokF7QIjJSGJBGDxSWkIKuGhrAnW4fYmWZRJRJjuftHYICJszp10ufSBA/9h7H7/p13LL58zB4b8EV7e0yQkGHND+JmLSvstyWTRECM1FdcUuFn+YGYuWbgJIJtnwRd34="
	vsb, _ := base64.StdEncoding.DecodeString(vs)

	pk, _ := e.decrypt(vsb[12:], vsb[:12])
	pks := string(pk)
	pkss, _ := base64.StdEncoding.DecodeString(pks)
	pksss := base58.Encode(pkss)
	fmt.Println(pks, pksss)
}

package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/mr-tron/base58"
)

func TestSec(t *testing.T) {
	s := "5GhfLYDExhaBTaWpwbfTk6DrMYdv8vkiFLwgdbz2vouzxe2dxy6RNGB13ozz9ns7RjLZoLHMGJK5jZtFJpxYhzWn"
	bs, _ := base58.Decode(s)
	e := Porter()
	// e.SetAESKey("my_secret_seed_value")
	bss, err := e.Encrypt(bs)

	block, err := aes.NewCipher(e.aesKey)

	// 使用 GCM 模式
	aesGCM, err := cipher.NewGCM(block)
	nonceSize := aesGCM.NonceSize() // 从加密逻辑中获取的 nonce size
	if len(bss) <= nonceSize {
		t.Fatalf("Ciphertext too short")
	}

	// 分离 nonce 和 ciphertext
	nonce, ciphertext := bss[:nonceSize], bss[nonceSize:]

	bsss, err := e.decrypt(ciphertext, nonce)
	bssss := string(bsss)

	result := base64.StdEncoding.EncodeToString(bss)
	fmt.Println(result, err, bssss)

	vs := "QdYipjM+H/NiQxG4yXg1azMms7cokF7QIjJSGJBGDxSWkIKuGhrAnW4fYmWZRJRJjuftHYICJszp10ufSBA/9h7H7/p13LL58zB4b8EV7e0yQkGHND+JmLSvstyWTRECM1FdcUuFn+YGYuWbgJIJtnwRd34="
	vsb, err := base64.StdEncoding.DecodeString(vs)

	pk, err := e.decrypt(vsb[12:], vsb[:12])
	pks := string(pk)
	pkss, _ := base64.StdEncoding.DecodeString(pks)
	pksss := base58.Encode(pkss)
	fmt.Println(pks, pksss)
}

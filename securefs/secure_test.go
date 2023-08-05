package securefs

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestAES(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plainText := []byte("This is test string")

	iv := []byte("1234567887654321")

	ciphertext, err := AESEncrypt(plainText, key, iv)
	if err != nil {
		t.Fatal("encrypt:", err)
	}

	// fmt.Println("plainText len=", len(plainText))
	// fmt.Println("ciphertext len=", len(ciphertext))
	// fmt.Println("iv=", string(iv))
	// fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))

	givenString := base64.StdEncoding.EncodeToString(ciphertext)
	// givenString := "GDYQZ081R67VAEUEYbIoFw=="
	decodedString, err := base64.StdEncoding.DecodeString(givenString)
	if err != nil {
		fmt.Println("Error DecodeString:", err)
		return
	}

	decryptText, err := AESDecrypt(decodedString, key, iv)
	if err != nil {
		t.Fatal("decrypt:", err)
	}

	if string(plainText) != string(decryptText) {
		t.Fatalf("decrypt not equal: %s != %s", string(plainText), string(decryptText))
	}
}

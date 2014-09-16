package icecrypt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestIcecrypt(t *testing.T) {

	key := CreateKey();
	iv := CreateIV()
	fmt.Println("key length is", len(key))
	fmt.Println("Got key", base64.StdEncoding.EncodeToString(key))

	plaintext := []byte("Secret to encrypt.")
	auth_data := []byte("scrt")

	cipher_text, err := Encrypt(plaintext, key, iv, auth_data)
	if (err != nil) {
		t.Fatal(err)
	}

	fmt.Println("Got ct", base64.StdEncoding.EncodeToString(cipher_text))

	plaintext2, err := Decrypt(cipher_text, key, iv, auth_data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, plaintext2) {
		t.Error("Decrypt failed")
	}
}

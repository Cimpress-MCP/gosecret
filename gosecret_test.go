package gosecret

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path"
	"testing"
)

func TestEncrypt(t *testing.T) {

	key := CreateKey()
	iv := CreateIV()
	fmt.Println("key length is", len(key))
	fmt.Println("Got key", base64.StdEncoding.EncodeToString(key))

	plaintext := []byte("Secret to encrypt.")
	auth_data := []byte("scrt")

	cipher_text, err := encrypt(plaintext, key, iv, auth_data)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Got ct", base64.StdEncoding.EncodeToString(cipher_text))

	plaintext2, err := decrypt(cipher_text, key, iv, auth_data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, plaintext2) {
		t.Error("Decrypt failed")
	}
}

func TestDecryptFile(t *testing.T) {

	plaintextFile, err := ioutil.ReadFile(path.Join("test_data", "config_plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile(path.Join("test_data", "config_enc.json"))
	if err != nil {
		t.Fatal(err)
	}

	fileContents, err := DecryptTags(file, "test_keys")

	fmt.Printf(string(fileContents))

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintextFile, fileContents) {
		t.Error("Decrypt failed")
	}
}

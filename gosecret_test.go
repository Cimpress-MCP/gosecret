package gosecret

import (
	"bytes"
	"io/ioutil"
	"path"
	"testing"
)

func TestEncrypt(t *testing.T) {

	key := CreateKey()
	iv := CreateIV()

	plaintext := []byte("Secret to encrypt.")
	auth_data := []byte("scrt")

	cipher_text, err := encrypt(plaintext, key, iv, auth_data)
	if err != nil {
		t.Fatal(err)
	}

	plaintext2, err := decrypt(cipher_text, key, iv, auth_data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, plaintext2) {
		t.Error("Decrypt failed")
	}
}

func TestEncryptFile(t *testing.T) {

	plaintextFile, err := ioutil.ReadFile(path.Join("test_data", "config_plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile(path.Join("test_data", "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptTags(file, "myteamkey-2014-09-19", "test_keys", false)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptTags(encrypted, "test_keys")

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintextFile, decrypted) {
		t.Error("Encrypt / Decrypt round-trip failed")
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

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintextFile, fileContents) {
		t.Error("Decrypt failed")
	}
}

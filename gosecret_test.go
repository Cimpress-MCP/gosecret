package gosecret

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"os"
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

func TestNoopEncryptFile(t *testing.T) {

	var original []byte = []byte("This string is not encrypted.  It should be returned without modification.")

	notEncrypted, err := EncryptTags(original, "myteamkey-2014-09-19", "test_keys", false)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(original, notEncrypted) {
		t.Error("No-op encryption failed")
	}
}

func TestNoopDecryptFile(t *testing.T) {

	var original []byte = []byte("This string is not encrypted.  It should be returned without modification.")

	notDecrypted, err := DecryptTags(original, "test_keys")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(original, notDecrypted) {
		t.Error("No-op decryption failed")
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

func TestKeyRotation(t *testing.T) {

	os.Remove(path.Join("test_keys", "test_key_1"))
	os.Remove(path.Join("test_keys", "test_key_2"))

	plaintextFile, err := ioutil.ReadFile(path.Join("test_data", "config_plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile(path.Join("test_data", "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Create a new key.  Use it to encrypt.
	err = ioutil.WriteFile(path.Join("test_keys", "test_key_1"), []byte(base64.StdEncoding.EncodeToString(CreateKey())), 0666)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptTags(file, "test_key_1", "test_keys", false)
	if err != nil {
		t.Fatal(err)
	}

	// Create another new key.  Use it to re-encrypt.
	err = ioutil.WriteFile(path.Join("test_keys", "test_key_2"), []byte(base64.StdEncoding.EncodeToString(CreateKey())), 0666)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err = EncryptTags(file, "test_key_2", "test_keys", true)
	if err != nil {
		t.Fatal(err)
	}

	// Delete the first key.
	err = os.Remove(path.Join("test_keys", "test_key_1"))
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt the file
	decrypted, err := DecryptTags(encrypted, "test_keys")
	if err != nil {
		t.Fatal(err)
	}

	os.Remove(path.Join("test_keys", "test_key_2"))

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

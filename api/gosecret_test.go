package api

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestEncrypTag(t *testing.T) {

	et := EncryptionTag{
		[]byte("MySql Password"),
		[]byte( "kadjf454nkklz"),
		"myteamkey-2014-09-19",
	}

	keystore := path.Clean("../test_keys")
	iv := CreateIV()

	cipherText, err := et.EncryptTag(keystore, iv)
	if err != nil {
		t.Fatal(err)
	}

	dt := DecryptionTag {
		[]byte("MySql Password"),
		cipherText,
		iv,
		"myteamkey-2014-09-19",
	}

	plaintext, err := dt.DecryptTag(keystore)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, []byte("kadjf454nkklz")) {
		t.Error("Decrypt failed")
	}
}

func TestParsingTag(t *testing.T) {
	keystore := path.Clean("../test_keys")

	dt, err := ParseEncrytionTag(keystore, "MySql Password", "kadjf454nkklz", "myteamkey-2014-09-19")
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := ParseDecryptionTag(keystore, string(dt.AuthData), base64.StdEncoding.EncodeToString(dt.CipherText), base64.StdEncoding.EncodeToString(dt.InitVector), dt.KeyName)
	if err != nil {
		t.Fatal(err)
	}

	if !(plaintext == "kadjf454nkklz") {
		t.Error("Decrypt failed")
	}
}

///////////////////
// End of new tests
///////////////////

func TestEncrypt(t *testing.T) {

	key := CreateKey()
	iv := CreateIV()

	plaintext := []byte("Secret to encrypt.")
	auth_data := []byte("scrt")

	cipher_text, err := Encrypt(plaintext, key, iv, auth_data)
	if err != nil {
		t.Fatal(err)
	}

	plaintext2, err := Decrypt(cipher_text, key, iv, auth_data)
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

func TestEncryptSpecialCharacterFile(t *testing.T) {

	plaintextFile, err := ioutil.ReadFile(path.Join("../test_data", "config_special_characters_plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile(path.Join("../test_data", "config_special_characters.json"))
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptTags(file, "myteamkey-2014-09-19", "../test_keys", false)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptTags(encrypted, "../test_keys")

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintextFile, decrypted) {
		t.Error("Encrypt / Decrypt round-trip failed")
	}
}

func TestEncryptFile(t *testing.T) {

	plaintextFile, err := ioutil.ReadFile(path.Join("../test_data", "config_plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile(path.Join("../test_data", "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptTags(file, "myteamkey-2014-09-19", "../test_keys", false)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptTags(encrypted, "../test_keys")

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

	plaintextFile, err := ioutil.ReadFile(path.Join("../test_data", "config_plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile(path.Join("../test_data", "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Create a new key.  Use it to encrypt.
	rawKey := CreateKey()
	key := make([]byte, base64.StdEncoding.EncodedLen(len(rawKey)))
	base64.StdEncoding.Encode(key, rawKey)
	err = ioutil.WriteFile(path.Join("../test_keys", "test_key_1"), key, 0666)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptTags(file, "test_key_1", "../test_keys", false)
	if err != nil {
		t.Fatal(err)
	}

	// Create another new key.  Use it to re-encrypt.
	rawKey = CreateKey()
	key = make([]byte, base64.StdEncoding.EncodedLen(len(rawKey)))
	base64.StdEncoding.Encode(key, rawKey)
	err = ioutil.WriteFile(path.Join("../test_keys", "test_key_2"), key, 0666)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err = EncryptTags(file, "test_key_2", "../test_keys", true)
	if err != nil {
		t.Fatal(err)
	}

	// Delete the first key.
	err = os.Remove(path.Join("../test_keys", "test_key_1"))
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt the file
	decrypted, err := DecryptTags(encrypted, "../test_keys")
	if err != nil {
		t.Fatal(err)
	}

	os.Remove(path.Join("../test_keys", "test_key_2"))

	if !bytes.Equal(plaintextFile, decrypted) {
		t.Error("Encrypt / Decrypt round-trip failed")
	}
}

func TestDecryptFile(t *testing.T) {

	plaintextFile, err := ioutil.ReadFile(path.Join("../test_data", "config_plaintext.json"))
	if err != nil {
		t.Fatal(err)
	}

	file, err := ioutil.ReadFile(path.Join("../test_data", "config_enc.json"))
	if err != nil {
		t.Fatal(err)
	}

	fileContents, err := DecryptTags(file, "../test_keys")

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintextFile, fileContents) {
		t.Error("Decrypt failed")
	}
}

func BenchmarkEncryptFile(b *testing.B) {

	file, err := ioutil.ReadFile(path.Join("../test_data", "config.json"))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := EncryptTags(file, "myteamkey-2014-09-19", "../test_keys", false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptFile(b *testing.B) {

	file, err := ioutil.ReadFile(path.Join("../test_data", "config_enc.json"))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := DecryptTags(file, "../test_keys")
		if err != nil {
			b.Fatal(err)
		}
	}
}

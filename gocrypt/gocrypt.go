package gocrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

var gocryptRegex, _ = regexp.Compile("(\\[gocrypt\\|[^\\]]*)\\]")

/**
 * Icecrypt uses AES 256 GCM to encrypt and authenticate strings
 */
func createRandomBytes(length int) []byte {
	random_bytes := make([]byte, length)
	rand.Read(random_bytes)
	return random_bytes
}

func createKey() []byte {
	return createRandomBytes(32)
}

func createIV() []byte {
	return createRandomBytes(12)
}

func createCipher(key []byte) (cipher.AEAD, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	return aesgcm, nil
}

func encrypt(plaintext []byte, key []byte, iv []byte, ad []byte) ([]byte, error) {
	aesgcm, err := createCipher(key)
	if (err != nil) {
		return nil, err
	}
	return aesgcm.Seal(nil, iv, plaintext, ad), nil
}

func decrypt(ciphertext []byte, key []byte, iv []byte, ad []byte) ([]byte, error) {
	aesgcm, err := createCipher(key)
	if (err != nil) {
		return nil, err
	}

	return aesgcm.Open(nil, iv, ciphertext, ad)
}

func EncryptTags(buffer []byte, key []byte) ([]byte, error) {

	if (!utf8.Valid(buffer)) {
		return nil, errors.New("File is not valid UTF-8")
	}

	match := gocryptRegex.Match(buffer)
	fmt.Println("Match?", match)

	if (match) {
		matches := gocryptRegex.FindAll(buffer, -1)
		for _, match := range matches {
			fmt.Println("Match:", string(match))
		}
	}

	return buffer, nil;
}

func DecryptTags(buffer []byte, keyroot string) ([]byte, error) {

	if (!utf8.Valid(buffer)) {
		return nil, errors.New("File is not valid UTF-8")
	}

	match := gocryptRegex.Match(buffer)
	fmt.Println("Match?", match)

	if (match) {
		matches := gocryptRegex.FindAll(buffer, -1)
		for _, match := range matches {
			fmt.Println("Match:", string(match))
		}
	}

	return buffer, nil;
}


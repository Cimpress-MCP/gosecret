package main

import (
	"encoding/base64"
	"fmt"
	gosecret "github.com/cimpress-mcp/gosecret/api"
)

func goEncryptFunc(authtext string, plaintext string, keyname string) func(string) ([]byte, error) {
  iv := gosecret.CreateIV()
	cipherText, err := gosecret.Encrypt([]byte(plaintext), []byte(keyname), iv, []byte(authtext))
	if err != nil {
		return []byte(""), err
	}

	return []byte(fmt.Sprintf("{{goDecrypt \"%s\" \"%s\" \"%s\" \"%s\"}}",
		authtext,
		base64.StdEncoding.EncodeToString(cipherText),
		base64.StdEncoding.EncodeToString(iv),
		keyname)), nil
}

func goDecryptFunc(authtext string, ciphertext string, iv string, keyname string) func(string) (string, error) {
  ct, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		fmt.Println("Unable to decode ciphertext", ciphertext, err)
		return nil, err
	}

  // Not sure if same variable works
	t_iv, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		fmt.Println("Unable to decode IV", err)
		return nil, err
	}

	key, err := getBytesFromBase64File(filepath.Join(keyroot, keyname))
	if err != nil {
		fmt.Println("Unable to read file for decryption", err)
		return nil, err
	}

	plaintext, err := gosecret.Decrypt(ct, key, t_iv, []byte(authtext))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

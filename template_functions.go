package main

import (
	"fmt"
	"encoding/base64"
	gosecret "github.com/cimpress-mcp/gosecret/api"
)

func goEncryptFunc(keystore string) func(...string) (string, error) {
	return func(s ...string) (string, error) {
		dt, err := gosecret.ParseEncrytionTag(keystore, s...)
		if err != nil {
			fmt.Println("Unable to parse encryption tag", err)
			return "", err
		}

		// fmt.Println("Well, hello there")
		//
		// fmt.Printf("{{goDecrypt \"%s\" \"%s\" \"%s\" \"%s\"}}",
		// 	dt.AuthData,
		// 	dt.CipherText,
		// 	dt.InitVector,
		// 	dt.KeyName)

		return (fmt.Sprintf("{{goDecrypt \"%s\" \"%s\" \"%s\" \"%s\"}}",
			dt.AuthData,
			base64.StdEncoding.EncodeToString(dt.CipherText),
			base64.StdEncoding.EncodeToString(dt.InitVector),
			dt.KeyName)), nil
	}
}

// func goDecryptFunc(authtext string, ciphertext string, iv string, keyname string) func(string) (string, error) {
//   ct, err := base64.StdEncoding.DecodeString(ciphertext)
// 	if err != nil {
// 		fmt.Println("Unable to decode ciphertext", ciphertext, err)
// 		return nil, err
// 	}
//
//   // Not sure if same variable works
// 	t_iv, err := base64.StdEncoding.DecodeString(iv)
// 	if err != nil {
// 		fmt.Println("Unable to decode IV", err)
// 		return nil, err
// 	}
//
// 	key, err := getBytesFromBase64File(filepath.Join(keyroot, keyname))
// 	if err != nil {
// 		fmt.Println("Unable to read file for decryption", err)
// 		return nil, err
// 	}
//
// 	plaintext, err := gosecret.Decrypt(ct, key, t_iv, []byte(authtext))
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return plaintext, nil
// }

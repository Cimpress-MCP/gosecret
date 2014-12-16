package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"gosecret"
)

func main() {
	var mode string
	var value string
	var keystore string
	var keyname string
	var rotate bool
	var fileName string
	flag.Usage = usage
	flag.StringVar(
		&mode, "mode", "encrypt",
		"mode of operation, either keygen, encrypt, or decrypt; defaults to encrypt")
	flag.StringVar(
		&value, "value", "",
		"value to encrypt/decrypt in lieu of file")
	flag.StringVar(
		&keystore, "keystore", "/keys/",
		"directory in which keys are stored")
	flag.StringVar(
		&keyname, "key", "",
		"name of a key file to use for encryption")
	flag.BoolVar(
		&rotate, "rotate", true,
		"if encrypting, whether to rotate any already-encrypted tags to the new key")
	flag.Parse()
	if value == "" {
		if flag.NArg() != 1 {
			flag.Usage()
			return
		} else {
			fileName = flag.Args()[0]
		}
	}
	if (mode == "encrypt") {
		if (keyname == "") {
			fmt.Println("A -key must be provided for encryption")
			return
		}
		bytes := getBytes(value, fileName)

		fileContents, err := gosecret.EncryptTags(bytes, keyname, keystore, rotate)
		if (err != nil) {
			fmt.Println("encryption failed", err)
			return
		}

		fmt.Printf(string(fileContents))
	} else if (mode == "decrypt") {
		bytes := getBytes(value, fileName)
		fileContents, err := gosecret.DecryptTags(bytes, keystore)
		if (err != nil) {
			fmt.Println("err", err)
			return
		}
		fmt.Printf(string(fileContents))
	} else if (mode == "keygen") {
		key := gosecret.CreateKey()
		encodedKey := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
		base64.StdEncoding.Encode(encodedKey, key)
		ioutil.WriteFile(fileName, encodedKey, 0666)
	} else {
		fmt.Println("Unknown mode", mode)
	}

	return
}

func getBytes(value string, fileName string) []byte {
	if value != "" {
		return []byte(value)
	}
	file, err := ioutil.ReadFile(fileName)
	if (err != nil) {
		fmt.Println("Unable to read file for encryption", err)
		return nil
	}
	return file
}

func usage() {
	cmd := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, strings.TrimSpace(helpText)+"\n\n", cmd)
	flag.PrintDefaults()
}

const helpText = `
Usage: %s [options] file

  Encrypt or decrypt file using gosecret.

Options:
`

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"github.com/cimpress-mcp/gosecret"
)

func main() {
	var mode string
	var keystore string
	var keyname string
	var rotate bool
	flag.Usage = usage
	flag.StringVar(
		&mode, "mode", "encrypt",
		"mode of operation, either keygen, encrypt, or decrypt; defaults to encrypt")
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
	if flag.NArg() != 1 {
		flag.Usage()
		return
	}

	fileName := flag.Args()[0]

	if (mode == "encrypt") {
		if (keyname == "") {
			fmt.Println("A -key must be provided for encryption")
			return
		}

		file, err := ioutil.ReadFile(fileName)
		if (err != nil) {
			fmt.Println("Unable to read file for encryption", err)
			return
		}

		fileContents, err := gosecret.EncryptTags(file, keyname, keystore, rotate)
		if (err != nil) {
			fmt.Println("encryption failed", err)
			return
		}

		fmt.Printf(string(fileContents))
	} else if (mode == "decrypt") {
		file, err := ioutil.ReadFile(fileName)
		if (err != nil) {
			fmt.Println("err", err)
		}

		fileContents, err := gosecret.DecryptTags(file, keystore)
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

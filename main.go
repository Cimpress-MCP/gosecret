package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"github.com/ryanbreen/gocrypt/gocrypt"
)

func main() {
	var mode string
	var keystore string
	var key string
	flag.Usage = usage
	flag.StringVar(
		&mode, "mode", "encrypt",
		"mode of operation, either keygen, encrypt, or decrypt; defaults to encrypt")
	flag.StringVar(
		&keystore, "keystore", "/keys/",
		"directory in which keys are stored")
	flag.StringVar(
		&key, "key", "",
		"path to a key file to use for encryption")
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		return
	}

	fileName := flag.Args()[0]

	if (mode == "encrypt") {
		if (key == "") {
			fmt.Println("A -key must be provided for encryption")
			return
		}

		file, err := ioutil.ReadFile(fileName)
		if (err != nil) {
			fmt.Println("unable to read file for encryption", err)
			return
		}

		fileContents, err := gocrypt.EncryptTags(file, key)
		if (err != nil) {
			fmt.Println("encryption failed", err)
			return
		}
		fmt.Printf("Got file:\n%v\n", string(fileContents))
	} else if (mode == "decrypt") {
		file, err := ioutil.ReadFile(fileName)
		if (err != nil) {
			fmt.Println("err", err)
		}

		fileContents, err := gocrypt.DecryptTags(file, keystore)
		if (err != nil) {
			fmt.Println("err", err)
			return
		}
		fmt.Printf("Got file:\n%v\n", string(fileContents))
	} else if (mode == "keygen") {
		ioutil.WriteFile(fileName, []byte(base64.StdEncoding.EncodeToString(gocrypt.CreateKey())), 0666)
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

  Encrypt or decrypt file using gocrypt.

Options:
`

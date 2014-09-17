package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"github.com/ryanbreen/gocrypt/gocrypt"


	"io/ioutil"
)

func main() {
	var mode string
	var keystore string
	flag.Usage = usage
	flag.StringVar(
		&mode, "mode", "encrypt",
		"mode of operation, either keygen, encrypt, or decrypt; defaults to encrypt")
	flag.StringVar(
		&keystore, "keystore", "/keys/",
		"directory in which keys are stored")
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		return
	}

	file, err := ioutil.ReadFile(flag.Args()[0])
	if (err != nil) {
		fmt.Println("err", err)
	}

	if (mode == "encrypt") {
		fmt.Println("Encryption not yet supported")
		return
	} else if (mode == "decrypt") {
		fileContents, err := gocrypt.DecryptTags(file, "test_keys")
		if (err != nil) {
			fmt.Println("err", err)
			return
		}
		fmt.Printf("Got file:\n\n\n%v\n\n\n", string(fileContents))
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

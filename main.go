package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	gosecret "github.com/cimpress-mcp/gosecret/api"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
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
			return 1
		} else {
			fileName = flag.Args()[0]
		}
	}
	if (mode == "encrypt") {
		// if (keyname == "") {
		// 	fmt.Println("A -key must be provided for encryption")
		// 	return 2
		// }
		// bytes := getBytes(value, fileName)
		//
		// fileContents, err := gosecret.EncryptTags(bytes, keyname, keystore, rotate)
		// if (err != nil) {
		// 	fmt.Println("encryption failed", err)
		// 	return 4
		// }
		//
		// fmt.Println(string(fileContents))

		data := string(getBytes(value, fileName))

		// Create a template, add the function map, and parse the text.
		funcs := template.FuncMap {
	    // Template functions
	    "goEncrypt": goEncryptFunc(keystore),
	    //"goDecrypt": goDecryptFunc,
	  }

		tmpl, err := template.New("encryption").Funcs(funcs).Parse(data)
		if err != nil {
			fmt.Println("Could not parse template", err)
			return 99
		}

		// Run the template to verify the output.
		buff := new(bytes.Buffer)
		err = tmpl.Execute(buff, nil)
		if err != nil {
			fmt.Println("Could not execute template", err)
			return 98
		}

		fmt.Printf(string(buff.Bytes()))

	} else if (mode == "decrypt") {
		// bytes := getBytes(value, fileName)
		// fileContents, err := gosecret.DecryptTags(bytes, keystore)
		// if (err != nil) {
		// 	fmt.Println("err", err)
		// 	return 8
		// }
		// fmt.Printf(string(fileContents))

		data := string(getBytes(value, fileName))

		funcs := template.FuncMap {
	    // Template functions
	    //"goEncrypt": goEncryptFunc(keystore),
	    "goDecrypt": goDecryptFunc(keystore),
	  }

		tmpl, err := template.New("decryption").Funcs(funcs).Parse(data)
		if err != nil {
			fmt.Println("Could not parse template", err)
			return 99
		}

		// Run the template to verify the output.
		buff := new(bytes.Buffer)
		err = tmpl.Execute(buff, nil)
		if err != nil {
			fmt.Println("Could not execute template", err)
			return 98
		}

		fmt.Printf(string(buff.Bytes()))

	} else if (mode == "keygen") {
		key := gosecret.CreateKey()
		encodedKey := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
		base64.StdEncoding.Encode(encodedKey, key)
		ioutil.WriteFile(fileName, encodedKey, 0666)
	} else {
		fmt.Println("Unknown mode", mode)
		return 16
	}

	return 0
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

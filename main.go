package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
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
		&keystore, "keystore", "",
		"directory in which keys are stored")
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		return
	}

	usr, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return
	}
	fmt.Printf("gocrypt root path: %s%sgocrypt\n", usr.HomeDir, string(os.PathSeparator)) 

	//args := flag.Args()

	localPath := fmt.Sprintf("%s%sgocrypt", usr.HomeDir, string(os.PathSeparator))
	fmt.Println("localPath", localPath)

	file, err := ioutil.ReadFile("./test_data/config.json")
	if (err != nil) {
		fmt.Println("err", err)
	}

	fileContents, err := gocrypt.DecryptTags(file, "test_keys")

	fmt.Printf("Got file:\n\n\n%v\n\n\n", string(fileContents))

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

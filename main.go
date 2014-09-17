package gocrypt

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
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
	if flag.NArg() < 2 {
		flag.Usage()
		return
	}

	usr, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return
	}
	fmt.Printf("gocrypt root path: %s%sgocrypt\n", usr.HomeDir, string(os.PathSeparator)) 

	args := flag.Args()

	localPath := fmt.Sprintf("%s%sgocrypt%s", usr.HomeDir, string(os.PathSeparator), args[1])
	fmt.Println("localPath", localPath)

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

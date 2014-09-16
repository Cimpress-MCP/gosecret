package icecrypt

import (
	"errors"
	"fmt"
	"regexp"
	"io/ioutil"
	"unicode/utf8"
)

func EncryptFile(filename string, key []byte) ([]byte, error) {
	file, err := ioutil.ReadFile(filename)
	if (err != nil) {
		return nil, err;
	}

	if (!utf8.Valid(file)) {
		return nil, errors.New("File is not valid UTF-8")
	}

	regex, err := regexp.Compile("(\\[ice_encrypted\\|[^\\]]*)\\]")
	if (err != nil) {
		return nil, err;
	}

	match := regex.Match(file)
	fmt.Println("Match?", match)

	if (match) {
		matches := regex.FindAll(file, -1)
		for _, match := range matches {
			fmt.Println("Match:", string(match))
		}
	}

	return file, nil;
}

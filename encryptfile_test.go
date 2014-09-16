package icecrypt

import (
	"fmt"
	"testing"
)

func TestEncryptFile(t *testing.T) {

	fileContents, err := EncryptFile("./data/config.json", CreateKey())

	fmt.Printf("Got file:\n\n\n%v\n\n\n", string(fileContents))

	if err != nil {
		t.Fatal(err)
	}
}

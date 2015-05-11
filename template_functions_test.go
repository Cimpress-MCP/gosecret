package main

import (
	"path"
  "reflect"
	"testing"
)

func TestGoEncryptFunc(t *testing.T) {
	keystore := path.Clean("./test_keys")

	f := goEncryptFunc(keystore)

	result, err := f( "MySql Password", "kadjf454nkklz", "myteamkey-2014-09-19" )
	if err != nil {
		t.Fatal(err)
	}

  //Regexp on decryption tag
	expected := ""
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %q to be %q", result, expected)
	}
}

func TestGoDecryptFunc(t *testing.T) {
	keystore := path.Clean("./test_keys")

	f := goDecryptFunc(keystore)

	result, err := f( "MySql Password", "KAb40OjTPcnDZOwnkY5jQcTWrc2bA0Gen9WM2h4=", "f5qtnyK78Ac710T2", "myteamkey-2014-09-19" )
	if err != nil {
		t.Fatal(err)
	}

	expected := "kadjf454nkklz"
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %q to be %q", result, expected)
	}
}

// This repository provides the gosecret package for encrypting and decrypting all or part of a []byte using AES-256-GCM.
// gosecret was written to work with tools such as https://github.com/ryanbreen/git2consul,
// https://github.com/ryanbreen/fsconsul, and https://github.com/hashicorp/envconsul, providing a mechanism for storing
// and moving secure secrets around the network and decrypting them on target systems via a previously installed key.
//
// gosecret is built on the assumption that only part of any given file should be encrypted: in most configuration files,
// there are few fields that need to be encrypted and the rest can safely be left as plaintext.  gosecret can be used in a
// mode where the entire file is a single encrypted tag, but you should examine whether there's a good reason to do so.
//
// To signify that you wish a portion of a file to be encrypted, you need to denote that portion of the file with a tag.
// Imagine that your file contains this bit of JSON:
//
//	{ 'dbpassword': 'kadjf454nkklz' }
//
// To have gosecret encrypt just the password, you might create a tag like this:
//
//	{ 'dbpassword': '[gosecret|my mongo db password|kadjf454nkklz]' }
//
// The components of the tag are, in order:
//
// 	1. The gosecret header
//	2. An auth data string.
//	3. The plaintext we wish to encrypt.
//
// Note that auth data can be any string (as long as it doesn't contain the pipe character, '|').  This tag is hashed and
// included as part of the ciphertext.  It's helpful if this tag has some semantic meaning describing the encrypted data.
// Auth data string is not private data.  It is hashed and used as part of the ciphertext such that decryption will fail if
// any of auth data, initialization vector, and key are incorrect for a specific piece of ciphertext.  This increases the
// security of the encryption algorithm by obviating attacks that seek to learn about the key and initialization vector through
// repeated decryption attempts.
//
// With this tag in place, you can encrypt the file via 'gosecret-cli'.  The result will yield something that looks like this,
// assuming you encrypted it with a keyfile named 'myteamkey-2014-09-19':
//
//	{ 'dbpassword': '[gosecret|my mongo db password|TtRotEctptR1LfA5tSn3kAtzjyWjAp+dMOHe6lc=|FJA7qz+dUdubwv9G|myteamkey-2014-09-19]' }
//
// The components of the tag are, in order:
//
//	1. The gosecret header
//	2. The auth data string
//	3. The ciphertext, in Base64
//	4. The initialization vector, in Base64
//	5. The key name
//
// A key may be used any number of times, but a new initialization vector should be created each time the key is used.  This is
// handled for you automatically by gosecret.
//
// When this is decrypted by a system that contains key 'myteamkey-2014-09-19', the key and initialization vector are used to both
// authenticate the auth data string and (if authentic) decrypt the ciphertext back to plaintext.  This will result in the
// encrypted tag being replaced by the plaintext, returning us to our original form:
//
//	{ 'dbpassword': 'kadjf454nkklz' }
//
// A file can contain any number of goscecret tags, or the entire file can be a gosecret tag.  It's up to you as the application
// developer or system maintainer to decide what balance of security vs readability you desire.
package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

var gosecretRegex, _ = regexp.Compile("\\[(gosecret\\|[^\\]]*)\\]")

// Create a random array of bytes.  This is used to create keys and IVs.
func createRandomBytes(length int) []byte {
	random_bytes := make([]byte, length)
	rand.Read(random_bytes)
	return random_bytes
}

// Create a random 256-bit array suitable for use as an AES-256 cipher key.
func CreateKey() []byte {
	return createRandomBytes(32)
}

// Create a random initialization vector to use for encryption.  Each gosecret tag should have a different
// initialization vector.
func createIV() []byte {
	return createRandomBytes(12)
}

// Create an AES-256 GCM cipher for use by gosecret.  This is the only form of encryption supported by gosecret,
// and barring any major flaws being discovered 256-bit keys should be adequate for quite some time.
func createCipher(key []byte) (cipher.AEAD, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	return aesgcm, nil
}

// Given an input plaintext []byte and key, initialization vector, and auth data []bytes, encrypt the plaintext
// using an AES-GCM cipher and return a []byte containing the result.
func encrypt(plaintext, key, iv, ad []byte) ([]byte, error) {
	aesgcm, err := createCipher(key)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, iv, plaintext, ad), nil
}

// Given an input ciphertext []byte and the key, initialization vector, and auth data []bytes used to encrypt it,
// decrypt using an AES-GCM cipher and return a []byte containing the result.
func decrypt(ciphertext, key, iv, ad []byte) ([]byte, error) {
	aesgcm, err := createCipher(key)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, iv, ciphertext, ad)
}

// Given an input []byte of Base64 encoded data, return a slice containing the decoded data.
func decodeBase64(input []byte) ([]byte, error) {
	output := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
	l, err := base64.StdEncoding.Decode(output, input)

	if err != nil {
		return nil, err
	}

	return output[:l], nil
}

// Given a file path known to contain Base64 encoded data, return a slice containing the decoded data.
func getBytesFromBase64File(filepath string) ([]byte, error) {
	file, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Println("Unable to read file", err)
		return nil, err
	}

	return decodeBase64(file)
}

// Given an array of encrypted tag parts and a directory of keys, convert the encrypted gosecret tag into
// a plaintext []byte.
func decryptTag(tagParts []string, keyroot string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(tagParts[2])
	if err != nil {
		fmt.Println("Unable to decode ciphertext", tagParts[2], err)
		return nil, err
	}

	iv, err := base64.StdEncoding.DecodeString(tagParts[3])
	if err != nil {
		fmt.Println("Unable to decode IV", err)
		return nil, err
	}

	key, err := getBytesFromBase64File(filepath.Join(keyroot, tagParts[4]))
	if err != nil {
		fmt.Println("Unable to read file for decryption", err)
		return nil, err
	}

	plaintext, err := decrypt(ct, key, iv, []byte(tagParts[1]))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Given an array of unencrypted tag parts, a []byte containing the key, and a name for the key, generate
// an encrypted gosecret tag.
func encryptTag(tagParts []string, key []byte, keyname string) ([]byte, error) {
	iv := createIV()
	cipherText, err := encrypt([]byte(tagParts[2]), key, iv, []byte(tagParts[1]))
	if err != nil {
		return []byte(""), err
	}

	return []byte(fmt.Sprintf("[gosecret|%s|%s|%s|%s]",
		tagParts[1],
		base64.StdEncoding.EncodeToString(cipherText),
		base64.StdEncoding.EncodeToString(iv),
		keyname)), nil
}

// EncryptTags looks for any tagged data of the form [gosecret|authtext|plaintext] in the input content byte
// array and replaces each with an encrypted gosecret tag.  Note that the input content must be valid UTF-8.
// The second parameter is the name of the keyfile to use for encrypting all tags in the content, and the
// third parameter is the 256-bit key itself.
// EncryptTags returns a []byte with all unencrypted [gosecret] blocks replaced by encrypted gosecret tags.
func EncryptTags(content []byte, keyname, keyroot string, rotate bool) ([]byte, error) {

	if !utf8.Valid(content) {
		return nil, errors.New("File is not valid UTF-8")
	}

	match := gosecretRegex.Match(content)

	if match {

		keypath := filepath.Join(keyroot, keyname)
		key, err := getBytesFromBase64File(keypath)
		if err != nil {
			fmt.Println("Unable to read encryption key")
			return nil, err
		}

		content = gosecretRegex.ReplaceAllFunc(content, func(match []byte) []byte {
			matchString := string(match)
			matchString = matchString[:len(matchString)-1]
			parts := strings.Split(string(matchString), "|")

			if len(parts) > 3 {
				if rotate {
					plaintext, err := decryptTag(parts, keyroot)
					if err != nil {
						fmt.Println("Unable to decrypt ciphertext", parts[2], err)
						return nil
					}

					parts[2] = string(plaintext)

					replacement, err := encryptTag(parts, key, keyname)
					if err != nil {
						fmt.Println("Failed to encrypt tag", err)
						return nil
					}
					return replacement
				} else {
					return match
				}
			} else {
				replacement, err := encryptTag(parts, key, keyname)
				if err != nil {
					fmt.Println("Failed to encrypt tag", err)
					return nil
				}
				return replacement
			}
		})
	}

	return content, nil
}

// DecryptTags looks for any tagged data of the form [gosecret|authtext|ciphertext|initvector|keyname] in the
// input content byte array and replaces each with a decrypted version of the ciphertext.  Note that the
// input content must be valid UTF-8.  The second parameter is the path to the directory in which keyfiles
// live.  For each |keyname| in a gosecret block, there must be a corresponding file of the same name in the
// keystore directory.
// DecryptTags returns a []byte with all [gosecret] blocks replaced by plaintext.
func DecryptTags(content []byte, keyroot string) ([]byte, error) {

	if !utf8.Valid(content) {
		return nil, errors.New("File is not valid UTF-8")
	}

	content = gosecretRegex.ReplaceAllFunc(content, func(match []byte) []byte {
		matchString := string(match)
		matchString = matchString[:len(matchString)-1]
		parts := strings.Split(matchString, "|")

		if len(parts) < 5 {
			// Block is not encrypted.  Noop.
			return match
		} else {
			plaintext, err := decryptTag(parts, keyroot)
			if err != nil {
				fmt.Println("Unable to decrypt tag", err)
				return nil
			}

			return plaintext
		}
	})

	return content, nil
}

gosecret
========
[![Build Status](https://travis-ci.org/Cimpress-MCP/gosecret.svg?branch=master)][travis]
[![Download](https://api.bintray.com/packages/cimpress-mcp/Go/gosecret/images/download.svg)][bintray]
[![Go Documentation](http://img.shields.io/badge/go-documentation-blue.svg)][godocs]

[travis]: http://travis-ci.org/Cimpress-MCP/gosecret
[bintray]: https://bintray.com/cimpress-mcp/Go/gosecret/_latestVersion#files
[godocs]: http://godoc.org/github.com/Cimpress-MCP/gosecret/api


This repository provides the `gosecret` package for encrypting and decrypting all or part of a `[]byte` using AES-256-GCM.  gosecret was written to work with tools such as [git2consul](https://github.com/Cimpress-MCP/git2consul), [fsconsul](https://github.com/Cimpress-MCP/fsconsul), and [envconsul](https://github.com/hashicorp/envconsul), providing a mechanism for storing and moving secure secrets around the network and decrypting them on target systems via a previously installed key.

Details on the Galois/Counter Mode algorithm can be found [here](https://en.wikipedia.org/wiki/Galois/Counter_Mode).

Installation
------------

Download versioned binaries from [Bintray](https://bintray.com/cimpress-mcp/Go/gosecret/_latestVersion#files). Here's an example of how to automate the download:

```bash
# Download gosecret v0.5.0 from Bintray to the working directory
curl -L "https://bintray.com/artifact/download/cimpress-mcp/Go/v0.5.0/linux-amd64/gosecret" -o bin/gosecret
chmod +x ./bin/gosecret
```

Optionally, gosecret can be built and installed from source by cloning the repository and executing `go install`, which will install both the `gosecret` CLI to `$GOPATH/bin` and `github.com/cimpress-mcp/gosecret/api` to `$GOPATH/pkg`.

Using the native template system
--------------------------------

Gosecret supports using native template tags. The tag format is different from the one previously used by gosecret, which is currently deprecated and will be removed in the next major release.

Encrypting and decrypting keys require appropriate tags. In the case of encryption, gosecret will turn all `goEncrypt` tags to `goDecrypt` tags. Running gosecret in decryption mode will turn `goDecrypt` tags into plaintext data. Please note that quotes will need to be escaped if they are part of the plaintext.

#### The goEncrypt tag

`{{goEncrypt "Auth data" "Plaintext" "Key name"}}`

To encrypt:
```
$ ./gosecret -mode encrypt -keystore ./test_keys -key myteamkey-2014-09-19 ./test_data/template/config.json
{
  "dbpassword" : "{{goDecrypt "MySql Password" "LcKxOXJa2qx1Riof0tLKzXvKW93ukxgOOBhspoc=" "fpY9FRvJ+8Z7ko6M" "myteamkey-2014-09-19"}}"
}
```

#### The goDecrypt tag

`{{goDecrypt "Auth data" "Cipher text" "Initialization vector" "Key name"}}`

To decrypt:
```
$ ./gosecret -mode decrypt -keystore ./test_keys ./test_data/template/encrypted.json
{
  "dbpassword" : "kadjf454nkklz"  
}
```

#### Key generation

To generate a AES-256 key:

```
gosecret -mode keygen ./test_keys/myteamkey-2014-09-19
```

Documentation (deprecated)
-------------
### Caveats

* Security in gosecret is predicated upon the security of the target machines.  gosecret uses symmetric encryption, so any user with access to the key can decrypt all secrets encrypted with that key.
* gosecret is built on the assumption that only part of any given file should be encrypted: in most configuration files, there are few fields that need to be encrypted and the rest can safely be left as plaintext.  gosecret can be used in a mode where the entire file is a single encrypted tag, but you should examine whether there's a good reason to do so.

### How It Works

Imagine that you have a file called `config.json`, and this file contains some secure data, such as DB connection strings, but that most data can be world readable.  You would use `gosecret` to encrypt the private fields with a specific key.  You can then check that version of `config.json` into git and move it around the network using `git2consul`.  `fsconsul` will detect the encrypted portion of the file and automatically decrypt it provided that the encryption key is present on the target machine.

To signify that you wish a portion of a file to be encrypted, you need to denote that portion of the file with a tag.  Imagine that your file contains this bit of JSON:

    { 'dbpassword': 'kadjf454nkklz' }

To have gosecret encrypt just the password, you might create a tag like this:

    { 'dbpassword': '[gosecret|my mongo db password|kadjf454nkklz]' }

The components of the tag are, in order:

1. The gosecret header
2. An auth data string.  Note that this can be any string (as long as it doesn't contain the pipe character, `|`).  This tag is hashed and included as part of the ciphertext.  It's helpful if this tag has some semantic meaning describing the encrypted data.
3. The plaintext we wish to encrypt.

With this tag in place, you can encrypt the file via the `gosecret` executable.  The result will yield something that looks like this, assuming you encrypted it with a keyfile named `myteamkey-2014-09-19`:

    { 'dbpassword': '[gosecret|my mongo db password|TtRotEctptR1LfA5tSn3kAtzjyWjAp+dMOHe6lc=|FJA7qz+dUdubwv9G|myteamkey-2014-09-19]' }

The components of the tag are, in order:

1. The gosecret header
2. The auth data string
3. The ciphertext, in Base64
4. The initialization vector, in Base64
5. The key name

When this is decrypted by a system that contains key `myteamkey-2014-09-19`, the key and initialization vector are used to both authenticate the auth data string and (if authentic) decrypt the ciphertext back to plaintext.  This will result in the encrypted tag being replaced by the plaintext, returning us to our original form:

    { 'dbpassword': 'kadjf454nkklz' }

Note that the auth data string is not private data.  It is hashed and used as part of the ciphertext such that decryption will fail if any of auth data, initialization vector, and key are incorrect for a specific piece of ciphertext.  This increases the security of the encryption algorithm by obviating attacks that seek to learn about the key and initialization vector through repeated decryption attempts.

### The CLI

`gosecret` supports 3 modes of operation: `keygen`, `encrypt`, and `decrypt`.

#### keygen

`gosecret -mode=keygen path/to/keyfile`

The above command will generate a new AES-256 key and store it, Base64 encoded, in `path/to/keyfile`

#### encrypt

`gosecret -mode=encrypt -keystore=path/to/keystore -key=name_of_keyfile path/to/plaintext_file`

The above command will encrypt any unencrypted tags in `path/to/plaintext_file` using the key stored at `path/to/keyfile`.  The encrypted file is printed to stdout.

#### decrypt

`gosecret -mode=decrypt -keystore=path/to/keystore path/to/encrypted_file`

The above command will decrypt any encrypted tags in `path/to/encrypted_file`, using the directory `path/to/keystore` as the home for any key named in an encrypted tag.  The decrypted file is printed to stdout.

## Notes

**Deprecation notice:** Old templating system is deprecated and will be removed in future versions of gosecret.

Builds are automatically ran by Travis on any push or pull request.

Tagged builds are automatically published to bintray for OS X, Linux, and Windows.

Licensed under Apache 2.0

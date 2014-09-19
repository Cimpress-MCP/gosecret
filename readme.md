#### gocrypt

This repository provides the `gocrypt` package for encrypting and decrypting all or part of a `[]byte` using AES-256-GCM.  gocrypt was written to work with tools such as [git2consul](https://github.com/ryanbreen/git2consul), [fsconsul](https://github.com/ryanbreen/fsconsul), and [envconsul](https://github.com/hashicorp/envconsul), providing a mechanism for storing and moving secure secrets around the network and decrypting them on target systems via a previously installed key.

##### Documentation

The full documentation is available on [godoc](http://godoc.org/github.com/ryanbreen/gocrypt).

##### Installation

Install the `gocrypt` package with `go install` from the main directory, and install the CLI with `go install` from the `gocrypt-cli` directory.

##### Caveats

* Security in gocrypt is predicated upon the security of the target machines.  gocrypt uses symmetric encryption, so any user with access to the key can decrypt all secrets encrypted with that key.

##### How It Works

Imagine that you have a file called `config.json`, and this file contains some secure data, such as DB connection strings, but that most data can be world readable.  You would use `gocrypt` to encrypt the private fields with a specific key.  You can then check that version of `config.json` into git and move it around the network using `git2consul`.  `fsconsul` will detect the encrypted portion of the file and automatically decrypt it provided that the encryption key is present on the target machine.

##### The CLI

`gocrypt-cli` supports 3 modes of operation: `keygen`, `encrypt`, and `decrypt`.

###### keygen

`gocrypt-cli -mode=keygen path/to/keyfile`

The above command will generate a new AES-256 key and store it, Base64 encoded, in `path/to/keyfile`

###### encrypt

`gocrypt-cli -mode=encrypt -key=path/to/keyfile path/to/plaintext_file`

The above command will encrypt any unencrypted tags in `path/to/plaintext_file` using the key stored at `path/to/keyfile`.  The encrypted file is printed to stdout.

###### decrypt

`gocrypt-cli -mode=decrypt -keystore=path/to/keystore path/to/encrypted_file`

The above command will decrypt any encrypted tags in `path/to/encrypted_file`, using the directory `path/to/keystore` as the home for any key named in an encrypted tag.  The decrypted file is printed to stdout.

##### License

Apache 2.0

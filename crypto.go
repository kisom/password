package main

// crypto.go supplies the sealing and opening of the password
// store. It assumes the callers have either serialised the password
// store or are prepared to parse the raw bytes into a password store,
// and this file contains no understanding of *what* exactly is being
// stored.
//
// The blobs are secured using NaCl secretbox, with keys derived from
// Scrypt using strong parameters. Each time the file is stored, a new
// salt is generated which yields a new key to encrypt the blob. It is
// therefore deemed appropriate to use a randomly-generated nonce.

import (
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
	"github.com/gokyle/readpass"
)

// passphrase is currently global to facilitate caching the password
// during the lifetime of the program.
var passphrase []byte

// randBytes is a wrapper for retrieving a buffer of the requested
// size, filled with random data. On failure, it returns nil.
func randBytes(size int) []byte {
	p := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, p)
	if err != nil {
		p = nil
	}
	return p
}

const (
	keySize   = 32
	saltSize  = 32
	nonceSize = 24
)

// This is wrapper for generating a new random nonce.
func newNonce() *[nonceSize]byte {
	var nonce [nonceSize]byte
	p := randBytes(nonceSize)
	if p == nil {
		return nil
	}
	copy(nonce[:], p)
	return &nonce
}

// encrypt generates a random nonce and encrypts the input using
// NaCl's secretbox package. The nonce is prepended to the ciphertext.
func encrypt(key *[keySize]byte, in []byte) ([]byte, bool) {
	var out = make([]byte, nonceSize)
	nonce := newNonce()
	if nonce == nil {
		return nil, false
	}

	copy(out, nonce[:])
	out = secretbox.Seal(out, in, nonce, key)
	return out, true
}

// decrypt extracts the nonce from the ciphertext, and attempts to
// decrypt with NaCl's secretbox.
func decrypt(key *[keySize]byte, in []byte) ([]byte, bool) {
	if len(in) < nonceSize {
		return nil, false
	}
	var nonce [nonceSize]byte
	copy(nonce[:], in)
	return secretbox.Open(nil, in[nonceSize:], &nonce, key)
}

// zero wipes out a byte slice. This isn't a bulletproof option, as
// there are many other factors outside the control of the program
// that come into play. For example, if memory is swapped out, or if
// the machine is put to sleep, the program has no control over what
// happens to its memory. In order to combat this, we try to wipe
// memory as soon as it is no longer used. In some cases, this will be
// done with deferred statements to ensure it's done; in other cases
// it will make sense to do it right after the secret is used.
func zero(in []byte) {
	for i := range in {
		in[i] ^= in[i]
	}
}

// deriveKey applies Scrypt with very strong parameters to generate an
// encryption key from a passphrase and salt.
func deriveKey(passphrase []byte, salt []byte) *[keySize]byte {
	rawKey, err := scrypt.Key(passphrase, salt, 32768, 8, 4, keySize)
	if err != nil {
		return nil
	}

	var key [keySize]byte
	copy(key[:], rawKey)
	zero(rawKey)
	return &key
}

// decryptFile recovers a secured blob from a file, returning a byte
// slice for parsing by the caller. If the password (which is a global
// variable) is nil, the user will be prompted for a password.
func decryptFile(filename string) (data []byte, err error) {
	data, err = ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	salt := data[:saltSize]
	data = data[saltSize:]
	passphrase, err = readpass.PasswordPromptBytes("Password store passphrase: ")
	if err != nil {
		data = nil
		return
	}

	key := deriveKey(passphrase, salt)
	if key == nil {
		err = errors.New("password: failed to derive key with Scrypt")
		return
	}

	data, ok := decrypt(key, data)
	if !ok {
		err = errors.New("password: failed to decrypt password store")
	}
	return
}

// encryptFile securely stores the encoded blob under the filename. If
// the password (which is a global variable) is nil, the user will be
// prompted for it.
func encryptFile(filename string, encoded []byte) (err error) {
	salt := randBytes(saltSize)
	if salt == nil {
		err = errors.New("password: failed to generate new salt")
		return
	}
	defer zero(encoded)

	if passphrase == nil {
		passphrase, err = readpass.PasswordPromptBytes("Password store passphrase: ")
		if err != nil {
			return
		}
	}

	key := deriveKey(passphrase, salt)
	if key == nil {
		err = errors.New("password: failed to derive key with Scrypt")
		return
	}

	data, ok := encrypt(key, encoded)
	if !ok {
		data = nil
		err = errors.New("password: failed to encrypt data")
		return
	}

	data = append(salt, data...)
	err = ioutil.WriteFile(filename, data, 0600)
	return
}

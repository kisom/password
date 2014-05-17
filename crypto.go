package main

import (
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
	"github.com/gokyle/readpass"
)

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

func newNonce() *[nonceSize]byte {
	var nonce [nonceSize]byte
	p := randBytes(nonceSize)
	if p == nil {
		return nil
	}
	copy(nonce[:], p)
	return &nonce
}

func Encrypt(key *[keySize]byte, in []byte) ([]byte, bool) {
	var out = make([]byte, nonceSize)
	nonce := newNonce()
	if nonce == nil {
		return nil, false
	}

	copy(out, nonce[:])
	out = secretbox.Seal(out, in, nonce, key)
	return out, true
}

func Decrypt(key *[keySize]byte, in []byte) ([]byte, bool) {
	if len(in) < nonceSize {
		return nil, false
	}
	var nonce [nonceSize]byte
	copy(nonce[:], in)
	return secretbox.Open(nil, in[nonceSize:], &nonce, key)
}

func newSalt() []byte {
	return randBytes(saltSize)
}

func zero(in []byte) {
	for i := range in {
		in[i] ^= in[i]
	}
}

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

func decryptFile(filename string) (data []byte, err error) {
	data, err = ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	salt := data[:saltSize]
	data = data[saltSize:]
	passphrase, err = readpass.PasswordPromptBytes("Database passphrase: ")
	if err != nil {
		data = nil
		return
	}

	key := deriveKey(passphrase, salt)
	if key == nil {
		err = errors.New("otpc: failed to derive key with Scrypt")
		return
	}

	data, ok := Decrypt(key, data)
	if !ok {
		err = errors.New("otpc: failed to decrypt accounts")
	}
	return
}

func encryptFile(filename string, encoded []byte) (err error) {
	salt := newSalt()
	if salt == nil {
		err = errors.New("otpc: failed to generate new salt")
		return
	}
	defer zero(encoded)

	if passphrase == nil {
		passphrase, err = readpass.PasswordPromptBytes("Database passphrase: ")
		if err != nil {
			return
		}
	}

	key := deriveKey(passphrase, salt)
	if key == nil {
		err = errors.New("otpc: failed to derive key with Scrypt")
		return
	}

	data, ok := Encrypt(key, encoded)
	if !ok {
		data = nil
		err = errors.New("otpc: failed to encrypt data")
		return
	}

	data = append(salt, data...)
	err = ioutil.WriteFile(filename, data, 0600)
	return
}

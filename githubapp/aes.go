package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

const (
	nonceSize  = 12
	aesKeySize = 16
)

func encrypt(text string, key []byte) (string, error) {
	if text == "" {
		return "", nil
	}

	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func decrypt(text string, key []byte) (string, error) {
	if text == "" {
		return "", nil
	}

	ciphertext, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := ciphertext[:nonceSize]

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext[nonceSize:], nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func randomkey() ([]byte, error) {
	key := make([]byte, aesKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

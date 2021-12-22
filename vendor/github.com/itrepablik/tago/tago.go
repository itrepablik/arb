package tago

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// Encrypt is the encryptor of the classified text, remember to use the same secret key
// Save the IV somewhere safe, it will be used to decrypt the text
func Encrypt(text, secretKey string) (string, []byte, error) {
	// Check if the length of the secret key is 16, 24 or 32
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return "", nil, errors.New("secret key must be 16, 24 or 32 bytes")
	}

	// Check if the text is empty
	if strings.TrimSpace(text) == "" {
		return "", nil, errors.New("text must not be empty")
	}

	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", nil, err
	}

	// The IV needs to be unique
	iv, err := generateIV()
	if err != nil {
		return "", nil, err
	}

	plaintext := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	return base64.RawStdEncoding.EncodeToString(ciphertext), iv, nil
}

// Decrypt is the decryptor of the classified text, remember to use the same secret key
func Decrypt(text, secretKey string, iv []byte) (string, error) {
	// Check if the length of the secret key is 16, 24 or 32
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return "", errors.New("secret key must be 16, 24 or 32 bytes")
	}

	// Check if the text is empty
	if strings.TrimSpace(text) == "" {
		return "", errors.New("text must not be empty")
	}

	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.RawStdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)
	return string(plaintext), nil
}

// GenerateSecretKey is the function to generate a secured random secret key
// either 16, 24, or 32 bytes to select AES-128, AES-192 or AES-256
func GenerateSecretKey(byteSize int) (string, error) {
	if byteSize != 16 && byteSize != 24 && byteSize != 32 {
		return "", errors.New("secret key must be 16, 24 or 32 bytes")
	}

	secretKey, err := generateSecureRandomBytes(byteSize)
	if err != nil {
		return "", err
	}
	return string(secretKey), nil
}

// generateSecureRandomBytes is the function to generate a secure random byte array
func generateSecureRandomBytes(byteSize int) ([]byte, error) {
	b := make([]byte, byteSize)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// generateIV is the function to generate a random IV
// The AES block size in bytes is 16
func generateIV() ([]byte, error) {
	iv, err := generateSecureRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

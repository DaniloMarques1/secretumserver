package encrypt

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"strings"
)

var (
	ErrInvalidKey        = errors.New("Invalid encryption key")
	ErrInvalidPlainText  = errors.New("Invalid plain text")
	ErrInvalidCipherText = errors.New("Invalid cipher text")
)

const (
	PlainTextPartSize  = 16
	CipherTextPartSize = 32
)

// TODO better name?
type Encrypt interface {
	// will return the message encrypted
	EncryptMessage(plainText string) (string, error)
}

type encrypt struct {
	key []byte
}

func NewEncrypt() (Encrypt, error) {
	key := os.Getenv("ENCRYPT_KEY")
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	hashedKey, err := hash(key)
	if err != nil {
		return nil, err
	}

	e := &encrypt{}
	e.key = []byte(hashedKey[:32])

	return e, nil
}

// returns the message encrypted
func (e *encrypt) EncryptMessage(plainText string) (string, error) {
	parts, err := e.parsePlainTextParts(plainText)
	if err != nil {
		return "", err
	}
	c, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	encrypted := make([]byte, 0)
	for _, block := range parts {
		dst := make([]byte, aes.BlockSize)
		src := make([]byte, aes.BlockSize)
		copy(src, []byte(block))
		c.Encrypt(dst, src)
		encrypted = append(encrypted, dst...)
	}

	return hex.EncodeToString(encrypted), nil
}

// breaks the plainText into slice of 16 chars each element (the last element may not have 16 chars)
func (e *encrypt) parsePlainTextParts(plainText string) ([]string, error) {
	messageSize := len(plainText)
	if messageSize < PlainTextPartSize {
		return []string{plainText}, nil
	}
	partsSize := int(math.Ceil(float64(messageSize) / float64(PlainTextPartSize)))
	parts := make([]string, 0, partsSize)
	start := 0
	end := PlainTextPartSize
	for i := 0; i < partsSize; i++ {
		part := plainText[start:end]
		parts = append(parts, part)

		start += PlainTextPartSize
		end += PlainTextPartSize
		if end > messageSize {
			end = messageSize
		}
	}

	return parts, nil
}

// TODO better name?
type Decrypt interface {
	// will return the message decrypted
	DecryptMessage(cipherText string) (string, error)
}

type decrypt struct {
	key []byte
}

func NewDecrypt() (Decrypt, error) {
	key := os.Getenv("ENCRYPT_KEY")
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	hashedKey, err := hash(key)
	if err != nil {
		return nil, err
	}

	d := &decrypt{}
	d.key = []byte(hashedKey[:32])

	return d, nil
}

func (d *decrypt) DecryptMessage(cipherText string) (string, error) {
	parts, err := d.parseCipherText(cipherText)
	if err != nil {
		return "", err
	}

	decryptedMessage := make([]byte, 0)
	for _, part := range parts {
		cipherText, err := hex.DecodeString(part)
		if err != nil {
			return "", err
		}
		c, err := aes.NewCipher(d.key)
		if err != nil {
			return "", err
		}
		dst := make([]byte, len(cipherText))
		src := make([]byte, len(cipherText))
		copy(src, []byte(cipherText))
		c.Decrypt(dst, src)
		decryptedMessage = append(decryptedMessage, dst...)
	}
	out := string(decryptedMessage[:])
	out = strings.ReplaceAll(out, "\x00", "") // removing the null

	return out, nil
}

// returns the cipherText as blocks of 32 chars
func (d *decrypt) parseCipherText(cipherText string) ([]string, error) {
	cipherTextSize := len(cipherText)
	if cipherTextSize < CipherTextPartSize {
		return nil, ErrInvalidCipherText
	}

	start := 0
	end := CipherTextPartSize
	parts := make([]string, 0)
	partsSize := int(math.Ceil(float64(cipherTextSize) / float64(CipherTextPartSize)))
	for i := 0; i < partsSize; i++ {
		part := cipherText[start:end]
		parts = append(parts, part)

		start += CipherTextPartSize
		end += CipherTextPartSize
		if end > cipherTextSize {
			end = cipherTextSize
		}
	}

	return parts, nil
}

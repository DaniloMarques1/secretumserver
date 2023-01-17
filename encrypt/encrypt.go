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
	EncryptMessage() (string, error)
}

type encrypt struct {
	key       []byte
	plainText string
}

func NewEncrypt(message string) (Encrypt, error) {
	if len(message) == 0 {
		return nil, ErrInvalidPlainText
	}

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
	e.plainText = message

	return e, nil
}

// TODO: we need to break the message into a slice of strings
// where each string cannot have more then 16 chars
func (e *encrypt) parsePlainTextParts() ([]string, error) {
	messageSize := len(e.plainText)
	if messageSize < PlainTextPartSize {
		return []string{e.plainText}, nil
	}
	partsSize := int(math.Ceil(float64(messageSize) / float64(PlainTextPartSize)))
	parts := make([]string, 0, partsSize)
	start := 0
	end := PlainTextPartSize
	for i := 0; i < partsSize; i++ {
		part := e.plainText[start:end]
		parts = append(parts, part)

		start += PlainTextPartSize
		end += PlainTextPartSize
		if end > messageSize {
			end = messageSize
		}
	}

	return parts, nil
}

func (e *encrypt) EncryptMessage() (string, error) {
	parts, err := e.parsePlainTextParts()
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

// TODO better name?
type Decrypt interface {
	// will return the message decrypted
	DecryptMessage() (string, error)
}

type decrypt struct {
	key        []byte
	cipherText string // TODO better name?
}

func NewDecrypt(message string) (Decrypt, error) {
	if len(message) == 0 {
		return nil, ErrInvalidPlainText
	}
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
	d.cipherText = message

	return d, nil
}

func (d *decrypt) DecryptMessage() (string, error) {
	parts, err := d.parseCipherText()
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
	out = strings.ReplaceAll(out, "\x00", "")

	return out, nil
}

func (d *decrypt) parseCipherText() ([]string, error) {
	if len(d.cipherText) < CipherTextPartSize {
		return nil, ErrInvalidCipherText
	}

	start := 0
	end := CipherTextPartSize
	parts := make([]string, 0)
	partsSize := int(math.Ceil(float64(len(d.cipherText)) / float64(CipherTextPartSize)))
	for i := 0; i < partsSize; i++ {
		part := d.cipherText[start:end]
		parts = append(parts, part)
		start += CipherTextPartSize
		end += CipherTextPartSize
		if end > len(d.cipherText) {
			end = len(d.cipherText)
		}
	}

	return parts, nil
}

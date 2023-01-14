package encrypt

import (
	"crypto/aes"
	"encoding/hex"
	"os"
)

// TODO not working, fix it
func Decrypt(encryptedMessage string) (string, error) {
	key, err := hash(os.Getenv("ENCRYPT_KEY"))
	if err != nil {
		return "", err
	}
	key = key[:32]

	plainTextBytes, err := hex.DecodeString(encryptedMessage)
	if err != nil {
		return "", err
	}

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	msgBytes := make([]byte, len(plainTextBytes))
	c.Decrypt(msgBytes, []byte(plainTextBytes))

	return string(msgBytes[:]), nil
}

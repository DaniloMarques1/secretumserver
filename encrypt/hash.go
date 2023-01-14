package encrypt

import (
	"crypto/sha256"
	"encoding/hex"
)

func hash(message string) (string, error) {
	sha := sha256.New()
	if _, err := sha.Write([]byte(message)); err != nil {
		return "", err
	}

	return hex.EncodeToString(sha.Sum(nil)), nil
}

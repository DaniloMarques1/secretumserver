package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"log"
	"os"
)

func Encrypt(message string) (string, error) {
	key, err := hash(os.Getenv("ENCRYPT_KEY"))
	if err != nil {
		return "", err
	}
	key = key[:32]

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	var encryptedMessage []byte
	if len(message) <= aes.BlockSize {
		encryptedMessage = encrypt16BytesBlock(c, message)
	} else {
		encryptedMessage = encryptOver16BytesBlock(c, message)
	}

	return hex.EncodeToString(encryptedMessage), nil
}

func encrypt16BytesBlock(block cipher.Block, message string) []byte {
	byteSize := aes.BlockSize

	messageBytes := make([]byte, byteSize)
	encryptedBytes := make([]byte, byteSize)
	copy(messageBytes, []byte(message))

	block.Encrypt(encryptedBytes, messageBytes)

	return encryptedBytes
}

func encryptOver16BytesBlock(block cipher.Block, message string) []byte {
	log.Printf("We are here %v\n", len(message))
	encryptedMessage := make([]byte, 0)
	partsN := len(message) / 16
	log.Printf("parts n = %v\n", partsN)
	for i := 1; i <= partsN; i++ {
		end := 16 * i
		start := end - 16
		part := message[start:end]
		log.Printf("Part = %v\n", part)
		encryptedBlock := encrypt16BytesBlock(block, part)
		log.Printf("Encrypted block = %x\n", encryptedBlock)
		encryptedMessage = append(encryptedMessage, encryptedBlock...)
	}

	return encryptedMessage
}

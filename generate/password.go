package generate

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"
)

var specialCharsBindings = map[string]string{
	"a": "@",
	"b": "#",
	"c": "@",
	"d": "&",
	"e": "*",
	"f": "(",
	"g": ")",
	"h": "@",
	"i": "%",
	"j": "@",
	"k": "#",
	"l": "&",
	"m": "*",
	"n": "#",
	"o": "!",
	"p": "!!",
	"q": "#",
	"r": "&",
	"s": "&&",
	"t": "**",
	"u": "(",
	"v": ")",
	"w": "@",
	"x": "*",
	"y": "@",
	"z": "!",
	"A": "&",
	"B": "@@",
	"C": "!!",
	"D": "@",
	"E": "&",
	"F": "*",
	"G": ")",
	"H": "@",
	"I": "#",
	"J": "&",
	"K": "*",
	"L": "(",
	"M": "@",
	"N": "#",
	"O": "$$",
	"P": "&",
	"Q": "!",
	"R": "!!",
	"S": "@@",
	"T": "((",
	"U": "))",
	"V": "@$",
	"W": "&",
	"X": "@",
	"Y": "*",
	"Z": "!",
}

func GeneratePassword(keyphrase string) string {
	var password string
	keyphraseSize := len(keyphrase)

	// building special chars
	for i := 0; i < 12; i++ {
		idx := getRandomInt(0, keyphraseSize)
		specialChar := specialCharsBindings[string(keyphrase[idx])]
		password += specialChar
	}

	// 10 random numbers
	for i := 0; i < 10; i++ {
		password += fmt.Sprintf("%d", getRandomInt(0, 10))
	}

	// five random letters from the keyphrase
	for i := 0; i < 5; i++ {
		idx := getRandomInt(0, keyphraseSize)
		letter := keyphrase[idx]
		password += strings.ToUpper(string(letter))
	}

	// 10 random uppercase letters
	for i := 0; i < 10; i++ {
		asciiDecimal := getRandomInt(97, 123)
		log.Printf("%v\n", asciiDecimal)
		password += string(rune(asciiDecimal))
	}

	randomPasswordSize := getRandomInt(45, 60)
	randomPassword := make([]byte, 0, randomPasswordSize)

	// mix them up
	for i := 0; i < randomPasswordSize; i++ {
		idx := getRandomInt(0, len(password))
		randomPassword = append(randomPassword, password[idx])
	}

	return string(randomPassword)
}

func getRandomInt(start, end int) int {
	seed := rand.NewSource(time.Now().UnixNano())
	random := rand.New(seed)
	randomInt := start + random.Intn(end-start)
	return randomInt
}

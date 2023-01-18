package generate

import (
	"fmt"
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
	"j": "_",
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
	"w": "_",
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
	"S": "_",
	"T": "((",
	"U": "))",
	"V": "@$",
	"W": "&",
	"X": "@",
	"Y": "*",
	"Z": "!",
}

const (
	SpecialCharsQty     = 12
	NumbersQty          = 10
	LettersQty          = 5
	UpperCaseLettersQty = 10
)

const (
	MinPasswordSize = 15
	MaxPasswordSize = 45
)

// TODO refactor
func GeneratePassword(keyphrase string) string {
	var password string
	keyphraseSize := len(keyphrase)

	// building special chars
	for i := 0; i < SpecialCharsQty; i++ {
		idx := getRandomInt(0, keyphraseSize)
		specialChar := specialCharsBindings[string(keyphrase[idx])]
		password += specialChar
	}

	// 10 random numbers
	for i := 0; i < NumbersQty; i++ {
		password += fmt.Sprintf("%d", getRandomInt(0, 10))
	}

	// five random letters from the keyphrase
	for i := 0; i < LettersQty; i++ {
		idx := getRandomInt(0, keyphraseSize)
		letter := keyphrase[idx]
		password += strings.ToUpper(string(letter))
	}

	// 10 random uppercase letters
	for i := 0; i < UpperCaseLettersQty; i++ {
		asciiDecimal := getRandomInt(97, 123)
		password += string(rune(asciiDecimal))
	}

	randomPasswordSize := getRandomInt(MinPasswordSize, MaxPasswordSize)
	randomPassword := make([]byte, randomPasswordSize)

	// mix them up
	for i := 0; i < randomPasswordSize; i++ {
		idx := getRandomInt(0, len(password))
		randomPassword[i] = password[idx]
	}

	return string(randomPassword)
}

func getRandomInt(start, end int) int {
	seed := rand.NewSource(time.Now().UnixNano())
	random := rand.New(seed)
	randomInt := start + random.Intn(end-start)
	return randomInt
}

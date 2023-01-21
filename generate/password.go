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

type GeneratePassword struct {
	keyphraseSize      int
	keyphrase          string
	randomPassword     []byte
	randomPasswordSize int
	password           string
}

func NewGeneratePassword(keyphrase string) *GeneratePassword {
	gp := &GeneratePassword{}
	gp.keyphrase = keyphrase
	gp.keyphraseSize = len(keyphrase)
	gp.randomPasswordSize = gp.getRandomInt(MinPasswordSize, MaxPasswordSize)
	gp.randomPassword = make([]byte, gp.randomPasswordSize)

	return gp
}

func (gp *GeneratePassword) Generate() string {
	gp.formSpecialChars()
	gp.formNumbers()
	gp.formLettersFromTheKeyPhrase()
	gp.formUpperCaseLetters()
	gp.randomize()

	return string(gp.randomPassword)
}

func (gp *GeneratePassword) formSpecialChars() {
	for i := 0; i < SpecialCharsQty; i++ {
		idx := gp.getRandomInt(0, gp.keyphraseSize)
		specialChar := specialCharsBindings[string(gp.keyphrase[idx])]
		gp.password += specialChar
	}
}

func (gp *GeneratePassword) formNumbers() {
	for i := 0; i < NumbersQty; i++ {
		gp.password += fmt.Sprintf("%d", gp.getRandomInt(0, 10))
	}
}

func (gp *GeneratePassword) formLettersFromTheKeyPhrase() {
	for i := 0; i < LettersQty; i++ {
		idx := gp.getRandomInt(0, gp.keyphraseSize)
		letter := gp.keyphrase[idx]
		gp.password += strings.ToUpper(string(letter))
	}
}

func (gp *GeneratePassword) formUpperCaseLetters() {
	for i := 0; i < UpperCaseLettersQty; i++ {
		asciiDecimal := gp.getRandomInt(97, 123)
		gp.password += string(rune(asciiDecimal))
	}
}

func (gp *GeneratePassword) randomize() {
	passwordSize := len(gp.password)
	for i := 0; i < gp.randomPasswordSize; i++ {
		idx := gp.getRandomInt(0, passwordSize)
		gp.randomPassword[i] = gp.password[idx]
	}
}

func (gp GeneratePassword) getRandomInt(start, end int) int {
	seed := rand.NewSource(time.Now().UnixNano())
	random := rand.New(seed)
	randomInt := start + random.Intn(end-start)
	return randomInt
}

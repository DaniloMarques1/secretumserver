package token

import (
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	MasterId string
	jwt.StandardClaims
}

const ExpiresIn = 3600

func GetToken(masterId string) (string, error) {
	claims := &Claims{
		MasterId: masterId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + ExpiresIn,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(os.Getenv("JWT_KEY")))
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func ValidateToken(tokenStr string) (*Claims, error) {
	log.Println(tokenStr)
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_KEY")), nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

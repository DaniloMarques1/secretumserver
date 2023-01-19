package token

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	RefreshTokenType = iota
	AccessTokenType
)

type Claims struct {
	MasterId  string
	TokenType uint
	jwt.StandardClaims
}

const (
	AccessTokenExpiresIn  = 3600   // an hour in seconds
	RefreshTokenExpiresIn = 604800 // a week in seconds
)

type TokenResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int32 // how long in seconds the AccessToken will still be valid
}

func GetToken(masterId string) (*TokenResponse, error) {
	accessTokenClaims := &Claims{
		MasterId:  masterId,
		TokenType: AccessTokenType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + AccessTokenExpiresIn,
		},
	}
	accessToken, err := generateToken(accessTokenClaims)
	if err != nil {
		return nil, err
	}

	refreshTokenClaims := &Claims{
		MasterId:  masterId,
		TokenType: RefreshTokenType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + RefreshTokenExpiresIn,
		},
	}
	refreshToken, err := generateToken(refreshTokenClaims)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    AccessTokenExpiresIn,
	}, nil
}

func generateToken(claims *Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	key := []byte(os.Getenv("JWT_KEY"))
	tokenStr, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func ValidateAccessToken(tokenStr string) (*Claims, error) {
	claims, err := validateToken(tokenStr)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != AccessTokenType {
		return nil, errors.New("Invalid toke type")
	}

	return claims, nil
}

func ValidateRefreshToken(tokenStr string) (*Claims, error) {
	claims, err := validateToken(tokenStr)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != RefreshTokenType {
		return nil, errors.New("Invalid toke type")
	}

	return claims, nil
}

func validateToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_KEY")), nil
	})
	if err != nil {
		return nil, err
	}

	return claims, nil
}

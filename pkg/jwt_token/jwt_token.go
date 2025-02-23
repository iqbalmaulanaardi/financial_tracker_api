package jwt_token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const ExpirationDays int = 2

// Claims
type Claims struct {
	jwt.RegisteredClaims

	UserId  string `json:"user_id"`
	Expired bool   `json:"expired"`
}

func GetTokenExpiration() int64 {
	return (int64(ExpirationDays) * 24) * 60 * 60
}

// NewJWTtoken
func NewJWTtoken(secret string, claims Claims) (string, error) {

	claims.ExpiresAt = jwt.NewNumericDate(time.Now().AddDate(0, 0, ExpirationDays))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return t.SignedString([]byte(secret))

}

// ParseJWTtoken
func ParseJWTtoken(secret, tokenStr string) (Claims, error) {

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return Claims{}, err
	}

	if !token.Valid {
		return Claims{}, fmt.Errorf("JWT token is not valid")
	}

	parsedClaims, ok := token.Claims.(*Claims)
	if !ok {
		return Claims{}, fmt.Errorf("claims type assertion error")
	}

	if parsedClaims.ExpiresAt.Before(time.Now()) {
		parsedClaims.Expired = true
	}

	return *parsedClaims, nil
}

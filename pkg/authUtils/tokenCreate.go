package auth_utils_adapter

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/needsomesleeptd/annotater-core/models"
	auth_utils "github.com/needsomesleeptd/annotater-core/utilsPorts/authUtils"
	"github.com/pkg/errors"
)

var (
	ErrInvalidToken = errors.New("token is invalid")
	ErrParsingToken = errors.New("error parsing token")
)

type JWTTokenHandler struct {
}

func NewJWTTokenHandler() auth_utils.ITokenHandler {
	return JWTTokenHandler{}
}

func (hasher JWTTokenHandler) GenerateToken(credentials models.User, key string) (string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"exprires": time.Now().Add(time.Hour * 24),
			"login":    credentials.Login,
			"ID":       credentials.ID,
			"Role":     credentials.Role,
		})
	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("creating token err: %w", err)
	}

	return tokenString, nil
}

func (hasher JWTTokenHandler) ValidateToken(tokenString string, key string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})

	if err != nil {
		return ErrParsingToken
	}

	if !token.Valid {
		return ErrInvalidToken
	}

	return nil
}

func (hasher JWTTokenHandler) ParseToken(tokenString string, key string) (*auth_utils.Payload, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "auth.tokenhelper.GetRole error in parse")
	}

	payload := &auth_utils.Payload{
		Login: claims["login"].(string),
		ID:    uint64(claims["ID"].(float64)),
		Role:  models.Role(claims["Role"].(float64)),
	}

	return payload, nil
}
func ExtractTokenFromReq(r *http.Request) string {

	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	return token
}

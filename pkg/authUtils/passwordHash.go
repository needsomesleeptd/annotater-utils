package auth_utils_adapter

import (
	auth_utils "github.com/needsomesleeptd/annotater-core/utilsPorts/authUtils"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type PasswordCryptoHasher struct {
}

func NewPasswordHashCrypto() auth_utils.IPasswordHasher {
	return PasswordCryptoHasher{}
}

func (hasher PasswordCryptoHasher) GenerateHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Errorf("Error in generating hash for password %s", password)
	}
	return string(hash), nil
}

func (hasher PasswordCryptoHasher) ComparePasswordhash(password string, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return errors.Wrap(err, "Error in comparing hash and passwd")
	}
	return nil
}

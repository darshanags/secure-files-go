package kdf

import (
	"crypto/rand"

	"github.com/darshanags/secure-files-go/pkg/config"
	"golang.org/x/crypto/argon2"
)

func Kdf(password string, exSalt []byte) (s []byte, k []byte) {
	var salt []byte

	if len(exSalt) == 0 {

		salt = make([]byte, config.KdfSaltLength)
		rand.Read(salt)

	} else {

		salt = exSalt

	}

	key := argon2.IDKey([]byte(password), salt, config.KdfTimeCost, config.KdfMemoryCost, config.KdfParallelism, config.KdfKeyLength)

	return salt, key
}

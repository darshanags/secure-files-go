package kdf

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

func Kdf(password string, exSalt []byte) (s []byte, k []byte) {
	const (
		timeCost    = 4          // Iterations
		memoryCost  = 128 * 1024 // Memory (128 MB)
		parallelism = 4          // Threads
		keyLength   = 32         // Key size in bytes
		saltLength  = 16         // Salt size in bytes
	)

	var salt []byte

	if len(exSalt) == 0 {

		salt = make([]byte, saltLength)
		rand.Read(salt)

	} else {

		salt = exSalt

	}

	key := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, keyLength)

	return salt, key
}

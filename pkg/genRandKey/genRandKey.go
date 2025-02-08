package genrandkey

import (
	"crypto/rand"
	"fmt"
)

func GenRandKey(keySize int32, keyType string) (key []byte) {
	k := make([]byte, keySize)
	_, err := rand.Read(k)

	if err != nil {
		_ = fmt.Errorf("failed to generate %s: %w", keyType, err)
	}

	return k
}

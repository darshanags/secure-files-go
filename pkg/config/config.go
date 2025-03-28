package config

import "golang.org/x/crypto/chacha20poly1305"

const (
	KdfTimeCost                    = 4          // Iterations
	KdfMemoryCost                  = 128 * 1024 // Memory (128 MB)
	KdfParallelism                 = 4          // Threads
	KdfKeyLength                   = 32         // Key size in bytes
	KdfSaltLength                  = 16         // Salt size in bytes
	FileSignature           string = "CHAPOLYX"
	FileSignatureLength            = len(FileSignature)
	ChunkSize                      = 4096
	NonceSize                      = chacha20poly1305.NonceSize
	SaltSize                int64  = 16
	EncryptedDataEncKeySize int64  = 32
	AuthTagSize             int64  = 16
	MinFileSize             int64  = NonceSize + SaltSize + EncryptedDataEncKeySize + AuthTagSize + AuthTagSize
)

package encryptfile

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"

	genrandkey "github.com/darshanags/secure-files-go/internal/genRandKey"
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptFile(inputPath string, outputPath string, derivedKey []byte, salt []byte) error {

	const (
		chunkSize = 4096                       // Size of each chunk in bytes
		nonceSize = chacha20poly1305.NonceSize // Nonce size for ChaCha20-Poly1305
	)

	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	dataEncKey := genrandkey.GenRandKey(chacha20poly1305.KeySize, "data encryption key")
	nonce := genrandkey.GenRandKey(nonceSize, "nonce")

	dataEncKeyCipher, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	encDataEncKey := dataEncKeyCipher.Seal(nil, nonce, dataEncKey, nil)

	headerData := slices.Concat(nonce, salt, encDataEncKey)

	// fmt.Println("nonce: ", nonce)
	// fmt.Println("salt: ", salt)
	// fmt.Println("encDataEncKey: ", encDataEncKey)
	fmt.Println("headerData: ", hex.EncodeToString(headerData))

	if _, err := outFile.Write(headerData); err != nil {
		_ = fmt.Errorf("failed to write header data: %w", err)
	}

	// Create the ChaCha20-Poly1305 cipher
	fileDataCipher, err := chacha20poly1305.New(dataEncKey)
	if err != nil {
		_ = fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt the file in chunks
	chunk := make([]byte, chunkSize)
	chunkIndex := uint64(0)

	for {
		// Read a chunk from the input file
		n, err := inFile.Read(chunk)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}
		if n == 0 {
			break
		}

		// Encrypt the chunk
		encryptedChunk := fileDataCipher.Seal(nil, nonce, chunk[:n], nil)

		// Write the encrypted chunk to the output file
		if _, err := outFile.Write(encryptedChunk); err != nil {
			return fmt.Errorf("failed to write encrypted chunk: %w", err)
		}

		// Increment the nonce for the next chunk
		chunkIndex++
		binary.LittleEndian.PutUint64(nonce[4:], chunkIndex)
	}

	return nil
}

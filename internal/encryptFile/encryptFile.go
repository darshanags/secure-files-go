package encryptfile

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"slices"

	genrandkey "github.com/darshanags/secure-files-go/internal/genRandKey"
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptFile(inputPath string, outputPath string, derivedKey []byte, salt []byte) error {

	const (
		chunkSize = 4096
		nonceSize = chacha20poly1305.NonceSize
	)

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	outFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
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

	if _, err := outFile.Write(headerData); err != nil {
		_ = fmt.Errorf("failed to write header data: %w", err)
	}

	fileDataCipher, err := chacha20poly1305.New(dataEncKey)
	if err != nil {
		_ = fmt.Errorf("failed to create cipher: %w", err)
	}

	chunk := make([]byte, chunkSize)
	chunkIndex := uint64(0)

	for {
		bytesRead, err := inputFile.Read(chunk)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}
		if bytesRead == 0 {
			break
		}

		encryptedChunk := fileDataCipher.Seal(nil, nonce, chunk[:bytesRead], nil)

		if _, err := outFile.Write(encryptedChunk); err != nil {
			return fmt.Errorf("failed to write encrypted chunk: %w", err)
		}

		chunkIndex++
		binary.LittleEndian.PutUint64(nonce[4:], chunkIndex)
	}

	return nil
}

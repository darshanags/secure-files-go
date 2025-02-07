package decryptfile

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/darshanags/secure-files-go/internal/kdf"
	"golang.org/x/crypto/chacha20poly1305"
)

func DecryptFile(inputPath string, outputPath string, password string) error {

	const (
		chunkSize                     = 4096
		nonceSize                     = chacha20poly1305.NonceSize
		saltSize                int64 = 16
		encryptedDataEncKeySize int64 = 32
		authTagSize             int64 = 16
		minFileSize             int64 = nonceSize + saltSize + encryptedDataEncKeySize + authTagSize + authTagSize
	)

	encryptedFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("could not open the input file: %w", err)
	}
	defer encryptedFile.Close()

	fileStat, err := encryptedFile.Stat()
	if err != nil {
		return fmt.Errorf("could not get encrypted file information: %w", err)
	}
	fileSize := fileStat.Size()

	if fileSize < minFileSize {
		return fmt.Errorf("invalid file format")
	}

	nonce := make([]byte, nonceSize)
	if _, err := encryptedFile.Read(nonce); err != nil {
		return fmt.Errorf("could not read the nonce: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err := encryptedFile.Read(salt); err != nil {
		return fmt.Errorf("could not read the salt: %w", err)
	}

	encryptedDataEncKey := make([]byte, encryptedDataEncKeySize+authTagSize)
	if _, err := encryptedFile.Read(encryptedDataEncKey); err != nil {
		return fmt.Errorf("could not read the secure encryption key: %w", err)
	}

	_, derivedKey := kdf.Kdf(password, salt)

	dataEncKeyCipher, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return fmt.Errorf("could not create key decryption cipher: %w", err)
	}

	decryptedDataEncKey, err := dataEncKeyCipher.Open(nil, nonce, encryptedDataEncKey, nil)
	if err != nil {
		return fmt.Errorf("could not decrypt the data encryption key, your password could be incorrect: %w", err)
	}

	outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	dataDecryptionCipher, err := chacha20poly1305.New(decryptedDataEncKey)
	if err != nil {
		return fmt.Errorf("could not create data decryption cipher: %w", err)
	}

	chunk := make([]byte, chunkSize+dataDecryptionCipher.Overhead())
	chunkIndex := uint64(0)
	totalBytesRead := 0

	for {
		bytesRead, err := encryptedFile.Read(chunk)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}
		if bytesRead == 0 {
			break
		}

		decryptedChunk, err := dataDecryptionCipher.Open(nil, nonce, chunk[:bytesRead], nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk: %w", err)
		}

		if _, err := outputFile.Write(decryptedChunk); err != nil {
			return fmt.Errorf("failed to write decrypted chunk: %w", err)
		}

		chunkIndex++
		binary.LittleEndian.PutUint64(nonce[4:], chunkIndex)
		totalBytesRead += bytesRead
	}

	fmt.Printf("File decrypted successfully! Total bytes processed: %d\n", totalBytesRead)

	return nil

}

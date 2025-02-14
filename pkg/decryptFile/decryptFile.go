package decryptfile

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/darshanags/secure-files-go/pkg/appparser"
	"github.com/darshanags/secure-files-go/pkg/config"
	"github.com/darshanags/secure-files-go/pkg/kdf"
	"golang.org/x/crypto/chacha20poly1305"
)

func DecryptFile(inputPath string, outputPath string, password string) (string, error) {

	message := ""

	encryptedFile, err := os.Open(inputPath)
	if err != nil {
		return message, fmt.Errorf("could not open the input file: %w", err)
	}
	defer encryptedFile.Close()

	fileStat, err := encryptedFile.Stat()
	if err != nil {
		return message, fmt.Errorf("could not get encrypted file information: %w", err)
	}
	fileSize := fileStat.Size()

	if fileSize < config.MinFileSize {
		return message, fmt.Errorf("invalid file format: minimum file size mismatch")
	}

	fileSignature, err := appparser.GetFileSignature(encryptedFile, "")
	if err != nil {
		return message, err
	}

	if _, err := appparser.IsValidFileSignature(fileSignature); err != nil {
		return message, err
	}

	nonce := make([]byte, config.NonceSize)
	if _, err := encryptedFile.Read(nonce); err != nil {
		return message, fmt.Errorf("could not read the nonce: %w", err)
	}

	salt := make([]byte, config.SaltSize)
	if _, err := encryptedFile.Read(salt); err != nil {
		return message, fmt.Errorf("could not read the salt: %w", err)
	}

	encryptedDataEncKey := make([]byte, config.EncryptedDataEncKeySize+config.AuthTagSize)
	if _, err := encryptedFile.Read(encryptedDataEncKey); err != nil {
		return message, fmt.Errorf("could not read the secure encryption key: %w", err)
	}

	_, derivedKey := kdf.Kdf(password, salt)

	dataEncKeyCipher, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return message, fmt.Errorf("could not create key decryption cipher: %w", err)
	}

	decryptedDataEncKey, err := dataEncKeyCipher.Open(nil, nonce, encryptedDataEncKey, nil)
	if err != nil {
		return message, fmt.Errorf("%w - could not decrypt the data encryption key, either the password is incorrect or the encrypted file has been altered", err)
	}

	outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return message, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	dataDecryptionCipher, err := chacha20poly1305.New(decryptedDataEncKey)
	if err != nil {
		return message, fmt.Errorf("could not create data decryption cipher: %w", err)
	}

	chunk := make([]byte, config.ChunkSize+dataDecryptionCipher.Overhead())
	chunkIndex := uint64(0)
	totalBytesRead := 0

	for {
		bytesRead, err := encryptedFile.Read(chunk)
		if err != nil && err != io.EOF {
			return message, fmt.Errorf("failed to read chunk: %w", err)
		}
		if bytesRead == 0 {
			break
		}

		decryptedChunk, err := dataDecryptionCipher.Open(nil, nonce, chunk[:bytesRead], nil)
		if err != nil {
			return message, fmt.Errorf("failed to decrypt chunk: %w", err)
		}

		if _, err := outputFile.Write(decryptedChunk); err != nil {
			return message, fmt.Errorf("failed to write decrypted chunk: %w", err)
		}

		chunkIndex++
		binary.LittleEndian.PutUint64(nonce[4:], chunkIndex)
		totalBytesRead += bytesRead
	}

	message = fmt.Sprintf("File decrypted successfully! Total bytes processed: %d", totalBytesRead)

	return message, nil

}

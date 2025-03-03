package encryptfile

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/darshanags/secure-files-go/pkg/config"
	genrandkey "github.com/darshanags/secure-files-go/pkg/genRandKey"
	"github.com/darshanags/secure-files-go/pkg/utilities"
	"golang.org/x/crypto/chacha20poly1305"
)

type LocalFileInfo utilities.FileInfo

func EncryptFile(inputPath string, outputPath string, derivedKey []byte, salt []byte) (string, error) {

	message := ""
	start := time.Now()

	inputFile, err := os.Open(inputPath)

	if err != nil {
		return message, fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	outFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return message, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	dataEncKey := genrandkey.GenRandKey(chacha20poly1305.KeySize, "data encryption key")
	nonce := genrandkey.GenRandKey(config.NonceSize, "nonce")

	dataEncKeyCipher, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return message, fmt.Errorf("failed to create cipher: %w", err)
	}

	encDataEncKey := dataEncKeyCipher.Seal(nil, nonce, dataEncKey, nil)

	headerData := slices.Concat([]byte(config.FileSignature), nonce, salt, encDataEncKey)

	if _, err := outFile.Write(headerData); err != nil {
		return message, fmt.Errorf("failed to write header data: %w", err)
	}

	fileDataCipher, err := chacha20poly1305.New(dataEncKey)
	if err != nil {
		return message, fmt.Errorf("failed to create cipher: %w", err)
	}

	chunk := make([]byte, config.ChunkSize)
	chunkIndex := uint64(0)
	var totalBytesRead uint64 = 0

	for {
		bytesRead, err := inputFile.Read(chunk)
		if err != nil && err != io.EOF {
			return message, fmt.Errorf("failed to read chunk: %w", err)
		}
		if bytesRead == 0 {
			break
		}

		encryptedChunk := fileDataCipher.Seal(nil, nonce, chunk[:bytesRead], nil)

		if _, err := outFile.Write(encryptedChunk); err != nil {
			return message, fmt.Errorf("failed to write encrypted chunk: %w", err)
		}

		chunkIndex++
		binary.LittleEndian.PutUint64(nonce[4:], chunkIndex)
		totalBytesRead += uint64(bytesRead)
	}

	message = fmt.Sprintf("File encrypted. %s processed in %s.", utilities.FormatFileSize(float64(totalBytesRead)), time.Since(start))

	return message, nil
}

func (file *LocalFileInfo) EncryptFileAsync(derivedKey []byte, salt []byte, wg *sync.WaitGroup, resultChannel chan<- utilities.AsyncResult) {
	defer wg.Done()
	start := time.Now()

	result := utilities.AsyncResult{
		Filename: file.InputFilename,
	}

	inputFile, err := os.Open(file.InputPath)
	if err != nil {
		result.Error = fmt.Errorf("failed to open input file: %w", err)
		resultChannel <- result
		return
	}
	defer inputFile.Close()

	outFile, err := os.OpenFile(file.OutputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		result.Error = fmt.Errorf("failed to create output file: %w", err)
		resultChannel <- result
		defer outFile.Close()
		return
	}
	defer outFile.Close()

	dataEncKey := genrandkey.GenRandKey(chacha20poly1305.KeySize, "data encryption key")
	nonce := genrandkey.GenRandKey(config.NonceSize, "nonce")

	dataEncKeyCipher, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		result.Error = fmt.Errorf("failed to create cipher: %w", err)
		resultChannel <- result
		return
	}

	encDataEncKey := dataEncKeyCipher.Seal(nil, nonce, dataEncKey, nil)

	headerData := slices.Concat([]byte(config.FileSignature), nonce, salt, encDataEncKey)

	if _, err := outFile.Write(headerData); err != nil {
		result.Error = fmt.Errorf("failed to write header data: %w", err)
		resultChannel <- result
		return
	}

	fileDataCipher, err := chacha20poly1305.New(dataEncKey)
	if err != nil {
		result.Error = fmt.Errorf("failed to create cipher: %w", err)
		resultChannel <- result
		return
	}

	chunk := make([]byte, config.ChunkSize)
	chunkIndex := uint64(0)
	var totalBytesRead uint64 = 0

	for {
		bytesRead, err := inputFile.Read(chunk)
		if err != nil && err != io.EOF {
			result.Error = fmt.Errorf("failed to read chunk: %w", err)
			resultChannel <- result
			return
		}
		if bytesRead == 0 {
			break
		}

		encryptedChunk := fileDataCipher.Seal(nil, nonce, chunk[:bytesRead], nil)

		if _, err := outFile.Write(encryptedChunk); err != nil {
			result.Error = fmt.Errorf("failed to write encrypted chunk: %w", err)
			resultChannel <- result
			return
		}

		chunkIndex++
		binary.LittleEndian.PutUint64(nonce[4:], chunkIndex)
		totalBytesRead += uint64(bytesRead)
	}

	resultChannel <- utilities.AsyncResult{
		Message: fmt.Sprintf("File encrypted: %s. %s processed in %s.", file.InputFilename, utilities.FormatFileSize(float64(totalBytesRead)), time.Since(start)),
	}
}

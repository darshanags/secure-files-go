package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/darshanags/secure-files-go/pkg/appparser"
	decryptfile "github.com/darshanags/secure-files-go/pkg/decryptFile"
	encryptfile "github.com/darshanags/secure-files-go/pkg/encryptFile"
	"github.com/darshanags/secure-files-go/pkg/kdf"
	"github.com/darshanags/secure-files-go/pkg/utilities"
)

func main() {

	progArgs := os.Args[1:]

	actions, err := appparser.CliParser(progArgs)
	if err != nil {
		log.Fatalln(err)
	}

	switch actions.Directive {
	case "enc":

		result := make(chan utilities.AsyncResult)
		salt, key := kdf.Kdf(actions.Password, nil)
		var wg sync.WaitGroup

		file := &encryptfile.LocalFileInfo{
			InputFilename:  actions.InputFilename,
			InputPath:      actions.InputPath,
			OutputFilename: actions.OutputFilename,
			OutputPath:     actions.OutputPath,
		}

		go file.EncryptFileAsync(key, salt, &wg, result)
		wg.Add(1)

		go func() {
			for result := range result {
				if result.Error != nil {
					log.Fatalln(result.Error)
				} else {
					fmt.Println(result.Message)
				}
			}
		}()

		wg.Wait()

		close(result)

	case "dec":
		result := make(chan utilities.AsyncResult)
		var wg sync.WaitGroup

		file := &decryptfile.LocalFileInfo{
			InputFilename:  actions.InputFilename,
			InputPath:      actions.InputPath,
			OutputFilename: actions.OutputFilename,
			OutputPath:     actions.OutputPath,
		}
		go file.DecryptFileAsync(actions.Password, &wg, result)
		wg.Add(1)

		go func() {
			for result := range result {
				if result.Error != nil {
					log.Fatalln(result.Error)
				} else {
					fmt.Println(result.Message)
				}
			}
		}()

		wg.Wait()

		close(result)

	}

}

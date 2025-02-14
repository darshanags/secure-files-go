package main

import (
	"fmt"
	"log"
	"os"

	"github.com/darshanags/secure-files-go/pkg/appparser"
	decryptfile "github.com/darshanags/secure-files-go/pkg/decryptFile"
	encryptfile "github.com/darshanags/secure-files-go/pkg/encryptFile"
	"github.com/darshanags/secure-files-go/pkg/kdf"
)

func main() {

	progArgs := os.Args[1:]

	actions, err := appparser.CliParser(progArgs)

	if err != nil {
		log.Fatalln(err)
	}

	switch actions.Directive {
	case "enc":
		salt, key := kdf.Kdf(actions.Password, nil)

		message, err := encryptfile.EncryptFile(actions.InputPath, actions.OutputPath, key, salt)

		if err != nil {
			log.Fatalln(err)
		} else {
			fmt.Println(message)
		}
	case "dec":
		message, err := decryptfile.DecryptFile(actions.InputPath, actions.OutputPath, actions.Password)

		if err != nil {
			log.Fatalln(err)
		} else {
			fmt.Println(message)
		}
	}

}

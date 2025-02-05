package main

import (
	"github.com/darshanags/secure-files-go/internal/kdf"
)

func main() {

	salt, key := kdf.Kdf("testpass", nil)

	//fmt.Println("Salt", salt)
	//fmt.Println("Key", key)

	//encryptfile.EncryptFile("test.txt", "test.txt.enc", key, salt)
}

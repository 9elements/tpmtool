package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm"
	"github.com/howeyc/gopass"
)

var (
	TPMio     io.ReadWriter
	tpmDevice string
        clearTPM
)

func init() {
	flag.StringVar(&tpmDevice, "tpm-dev", "/dev/tpm0", "TPM device path")
  flag.StringVar(&tpmDevice, "tpm-dev", "/dev/tpm0", "TPM device path")

	var err error
	TPMio, err = tpm.OpenTPM(tpmDevice)
	if err != nil {
		log.Fatal("Can't find tpm device!")
	}
}

func getAuth(name string) [20]byte {
	var auth [20]byte
	authInput := os.Getenv(name)
	if authInput != "" {
		aa := sha1.Sum([]byte(authInput))
		copy(auth[:], aa[:])
	}
	return auth
}

func getPass(prompt string) string {
	fmt.Printf(prompt)

	pass, err := gopass.GetPasswdMasked()
	if err != nil {
		log.Fatal("Couldn't get passphrase:")
	}

	return strings.TrimSpace(string(pass))
}

func main() {
	flag.Parse()


}

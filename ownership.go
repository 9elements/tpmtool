package main

import (
	"log"

	"github.com/google/go-tpm/tpm"
)

func TakeOwnership() {
	ownerAuth := getAuth(getPass("Please enter the owner passphrase: "))
	srkAuth := getAuth(getPass("Please enter the srk passphrase: "))

	pubek, err := tpm.ReadPubEK(TPMio)
	if err != nil {
		log.Fatal("Couldn't read the public endorsement key from the TPM:", err)
	}

	if err := tpm.TakeOwnership(TPMio, ownerAuth, srkAuth, pubek); err != nil {
		log.Fatal("Couldn't take ownership of the TPM:", err)
	}
}

func ClearOwnership() {
	ownerAuth := getAuth(getPass("Please enter the owner passphrase: "))

	if err := tpm.OwnerClear(TPMio, ownerAuth); err != nil {
		log.Fatal("Couldn't clear the TPM using owner auth:", err)
	}
}

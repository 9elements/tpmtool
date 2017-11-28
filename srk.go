package main

import (
	"log"

	"github.com/google/go-tpm/tpm"
)

const DEFAULT_LOCALITY = 0

func SealData(data []byte) []byte {
	srkAuth := getAuth(getPass("Please enter the srk passphrase: "))
	pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7, 8}

	sealed, err := tpm.Seal(TPMio, DEFAULT_LOCALITY, pcrs, data, srkAuth[:])
	if err != nil {
		log.Fatal("Couldn't seal the data:", err)
	}

	return sealed
}

func UnsealData(data []byte) []byte {
	srkAuth := getAuth(getPass("Please enter the srk passphrase: "))

	unsealed, err := tpm.Unseal(TPMio, data, srkAuth[:])
	if err != nil {
		log.Fatal("Couldn't unseal the data:", err)
	}

	return unsealed
}

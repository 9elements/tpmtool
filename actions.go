package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/insomniacslk/systemboot/pkg/tpm"
)

const (
	MaxPlatformConfigurationRegister = 24
	DefaultFilePermissions           = 660
)

func ShowStatus() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	summary := tpmInterface.Summary()
	fmt.Print(summary)

	if tpmInterface.Info().TemporarilyDeactivated {
		fmt.Println("\nError: Check your BIOS! TPM is temporary deactivated.")
	}

	if (!tpmInterface.Info().Active || !tpmInterface.Info().Enabled) && !tpmInterface.Info().TemporarilyDeactivated {
		fmt.Println("\nError: TPM is inactive or disabled! Check your BIOS physical presence settings.")
	}

	if !tpmInterface.Info().Owned {
		fmt.Println("\nError: TPM is not owned! Please take ownership of the TPM.")
	}

	tpmInterface.Close()

	return nil
}

func GetPubEk() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	var pubEk []byte
	pubEk, err = tpmInterface.ReadPubEK(*ekCommandPassword)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	if *ekCommandOutfile != "" {
		if err := ioutil.WriteFile(*ekCommandOutfile, pubEk, 660); err != nil {
			return err
		}
	}
	fingerprint := sha256.Sum256(pubEk)
	fmt.Printf("EK Pubkey fingerprint: 0x%x\n", fingerprint)

	return nil
}

func OwnTPM() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	err = tpmInterface.TakeOwnership(*ownerCommandPassword, *ownerCommandTakeSrkPassword)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	return nil
}

func ClearTPM() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	err = tpmInterface.ClearOwnership(*ownerCommandPassword)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	return nil
}

func ResetLockTPM() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	err = tpmInterface.ResetLock(*ownerCommandPassword)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	return nil
}

func Seal() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	for _, pcr := range *cryptoCommandSealPcrs {
		if pcr >= MaxPlatformConfigurationRegister || pcr < 0 {
			return errors.New("PCR index is incorrect")
		}
	}

	plainText, err := ioutil.ReadFile(*cryptoCommandSealPlainFile)
	if err != nil {
		return err
	}

	if tpmInterface.Info().Specification == tpm.TPM12 && len(plainText) > tpm.TPM12MaxKeySize {
		return errors.New("Plain text file is too big, max 2048 bytes")
	}

	sealed, err := tpmInterface.SealData(*cryptoCommandSealLocality, *cryptoCommandSealPcrs, plainText, *cryptoCommandSrkPassword)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	err = ioutil.WriteFile(*cryptoCommandSealCipherFile, sealed, 660)

	return err
}

func Unseal() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	cipherText, err := ioutil.ReadFile(*cryptoCommandUnsealCipherFile)
	if err != nil {
		return err
	}

	unsealed, err := tpmInterface.UnsealData(cipherText, *cryptoCommandSrkPassword)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	err = ioutil.WriteFile(*cryptoCommandUnsealPlainFile, unsealed, 660)

	return err
}

func PrintPcr() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	var pcrs string
	for i := uint32(0); i < MaxPlatformConfigurationRegister; i++ {
		hash, err := tpmInterface.ReadPCR(i)
		if err != nil {
			return err
		}
		pcrs += fmt.Sprintf("PCR-%02d: %x\n", i, hash)
	}
	tpmInterface.Close()
	fmt.Print(pcrs)

	return nil
}

func ReadPcr() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	if *pcrCommandReadIndex >= MaxPlatformConfigurationRegister || *pcrCommandReadIndex < 0 {
		return errors.New("PCR index is incorrect")
	}

	pcr, err := tpmInterface.ReadPCR(*pcrCommandReadIndex)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	fmt.Printf("PCR-%02d: %x\n", *pcrCommandReadIndex, pcr)

	return nil
}

func Measure() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	if *pcrCommandMeasureIndex >= MaxPlatformConfigurationRegister || *pcrCommandMeasureIndex < 0 {
		return errors.New("PCR index is incorrect")
	}

	fileToMeasure, err := ioutil.ReadFile(*pcrCommandMeasureFile)
	if err != nil {
		return err
	}

	err = tpmInterface.Measure(*pcrCommandMeasureIndex, fileToMeasure)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	return nil
}

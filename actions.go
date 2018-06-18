package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	//"path"
	"path/filepath"

	//"github.com/systemboot/systemboot/pkg/storage"
	"github.com/systemboot/systemboot/pkg/tpm"
)

const (
	MaxPlatformConfigurationRegister = 24
	DefaultFilePermissions           = 660
	Luks1HeaderLength                = 2048
)

func Status() error {
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

func Ek() error {
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

func OwnerTake() error {
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

func OwnerClear() error {
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

func OwnerResetLock() error {
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

func CryptoSeal() error {
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
		return errors.New("Plain text file is too big, max 256 bytes")
	}

	sealed, err := tpmInterface.SealData(*cryptoCommandSealLocality, *cryptoCommandSealPcrs, plainText, *cryptoCommandSrkPassword)
	if err != nil {
		return err
	}
	tpmInterface.Close()

	err = ioutil.WriteFile(*cryptoCommandSealCipherFile, sealed, 660)

	return err
}

func CryptoUnseal() error {
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

func PcrList() error {
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

func PcrRead() error {
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

func PcrMeasure() error {
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

func DiskFormat() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	keystorePath, err := MountKeystore()
	if err != nil {
		return err
	}

	randBytes := make([]byte, 64)
	if _, err = rand.Read(randBytes); err != nil {
		return err
	}

	if err = ioutil.WriteFile(keystorePath+"/plain", randBytes, 660); err != nil {
		return err
	}

	if !filepath.IsAbs(*diskCommandFormatDevice) {
		return err
	}

	err = CryptsetupFormat(keystorePath+"/plain", *diskCommandFormatDevice)
	if err != nil {
		return err
	}

	sealed, err := tpmInterface.SealData(*diskCommandFormatLocality, *diskCommandFormatPcrs, randBytes, "")
	if err != nil {
		return err
	}

	if !filepath.IsAbs(*diskCommandFormatFile) {
		return err
	}

	if err = ioutil.WriteFile(*diskCommandFormatFile, sealed, 660); err != nil {
		return err
	}

	return UnmountKeystore(keystorePath)
}

func DiskOpen() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	keystorePath, err := MountKeystore()
	if err != nil {
		return err
	}

	if !filepath.IsAbs(*diskCommandOpenSealFile) {
		return err
	}

	if !filepath.IsAbs(*diskCommandOpenDevice) {
		return err
	}

	if _, err := os.Stat(*diskCommandOpenMountPath); os.IsNotExist(err) {
		return err
	}

	sealedFile, err := ioutil.ReadFile(*diskCommandOpenSealFile)
	if err != nil {
		return err
	}

	sealed, err := tpmInterface.UnsealData(sealedFile, tpm.WellKnownSecret)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(keystorePath+"/plain", sealed, 660); err != nil {
		return err
	}

	deviceName, err := CryptsetupOpen(keystorePath+"/plain", *diskCommandOpenDevice)
	if err != nil {
		return err
	}

	fmt.Printf("Sealed encrypted device mounted with name: %s\n", deviceName)

	return UnmountKeystore(keystorePath)
}

func DiskClose() error {
	//deviceMapperPath := path.Join("/dev/mapper/", *diskCommandCloseName)
	//storage.GetMountpointByDevice(deviceMapperPath)
	return CryptsetupClose(*diskCommandCloseName)
}

func DiskExtend() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}

	if !filepath.IsAbs(*diskCommandExtendDevice) {
		return err
	}

	deviceFD, err := os.Open(*diskCommandExtendDevice)
	if err != nil {
		return err
	}
	defer deviceFD.Close()

	luksHeader := make([]byte, Luks1HeaderLength)
	_, err = deviceFD.Read(luksHeader)
	if err != nil {
		return err
	}

	return tpmInterface.Measure(*diskCommandExtendPcr, luksHeader)
}

func DiskReseal() error {
	return errors.New("Not implemented!")
}

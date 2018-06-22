package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"syscall"

	"github.com/systemboot/systemboot/pkg/storage"
	"github.com/systemboot/systemboot/pkg/tpm"
)

const (
	// MaxPlatformConfigurationRegister is the maximum number of PCRs
	MaxPlatformConfigurationRegister = 24
	// DefaultFilePermissions is the default write permission
	DefaultFilePermissions = 660
	// Luks1HeaderLength is the LUKS1 header length
	Luks1HeaderLength = 2048
)

// Status Dumps the tpm status
func Status() error {
	summary := TPMInterface.Summary()
	fmt.Print(summary)

	if TPMInterface.Info().TemporarilyDeactivated {
		fmt.Println("\nError: Check your BIOS! TPM is temporary deactivated.")
	}

	if (!TPMInterface.Info().Active || !TPMInterface.Info().Enabled) && !TPMInterface.Info().TemporarilyDeactivated {
		fmt.Println("\nError: TPM is inactive or disabled! Check your BIOS physical presence settings.")
	}

	if !TPMInterface.Info().Owned {
		fmt.Println("\nError: TPM is not owned! Please take ownership of the TPM.")
	}

	return nil
}

// Ek dumps the Endorsement Key
func Ek() error {
	var pubEk []byte
	pubEk, err := TPMInterface.ReadPubEK(*ekCommandPassword)
	if err != nil {
		return err
	}

	if *ekCommandOutfile != "" {
		if err := ioutil.WriteFile(*ekCommandOutfile, pubEk, 660); err != nil {
			return err
		}
	}
	fingerprint := sha256.Sum256(pubEk)
	fmt.Printf("EK Pubkey fingerprint: 0x%x\n", fingerprint)

	return nil
}

// OwnerTake takes ownership of the TPM
func OwnerTake() error {
	err := TPMInterface.TakeOwnership(*ownerCommandPassword, *ownerCommandTakeSrkPassword)
	if err != nil {
		return err
	}

	return nil
}

// OwnerClear clears ownership of the TPM
func OwnerClear() error {
	err := TPMInterface.ClearOwnership(*ownerCommandPassword)
	if err != nil {
		return err
	}

	return nil
}

// OwnerResetLock resets the TPM bruteforce lock
func OwnerResetLock() error {
	err := TPMInterface.ResetLock(*ownerCommandPassword)
	if err != nil {
		return err
	}

	return nil
}

// CryptoSeal seals data aganst PCR with TPM
func CryptoSeal() error {
	for _, pcr := range *cryptoCommandSealPcrs {
		if pcr >= MaxPlatformConfigurationRegister || pcr < 0 {
			return errors.New("PCR index is incorrect")
		}
	}

	plainText, err := ioutil.ReadFile(*cryptoCommandSealPlainFile)
	if err != nil {
		return err
	}

	if TPMInterface.Info().Specification == tpm.TPM12 && len(plainText) > tpm.TPM12MaxKeySize {
		return errors.New("Plain text file is too big, max 256 bytes")
	}

	sealed, err := TPMInterface.SealData(*cryptoCommandSealLocality, *cryptoCommandSealPcrs, plainText, *cryptoCommandSrkPassword)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(*cryptoCommandSealCipherFile, sealed, 660)
}

// CryptoUnseal unseals data by the TPM against PCR
func CryptoUnseal() error {
	cipherText, err := ioutil.ReadFile(*cryptoCommandUnsealCipherFile)
	if err != nil {
		return err
	}

	unsealed, err := TPMInterface.UnsealData(cipherText, *cryptoCommandSrkPassword)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(*cryptoCommandUnsealPlainFile, unsealed, 660)
}

// CryptoReseal reseals a data by given sealing configuration
func CryptoReseal() error {
	sealedFile, err := ioutil.ReadFile(*cryptoCommandResealKeyfile)
	if err != nil {
		return err
	}

	pcrInfo, err := PreCalculate(*cryptoCommandResealConfig)
	if err != nil {
		return err
	}

	unsealed, err := TPMInterface.UnsealData(sealedFile, *diskCommandSrkPassword)
	if err != nil {
		return err
	}

	sealed, err := TPMInterface.ResealData(tpm.DefaultLocality, pcrInfo, unsealed, *cryptoCommandSrkPassword)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(*cryptoCommandResealKeyfile, sealed, 660)
}

// PcrList dumps all PCRs
func PcrList() error {
	var pcrs string
	for i := uint32(0); i < MaxPlatformConfigurationRegister; i++ {
		hash, err := TPMInterface.ReadPCR(i)
		if err != nil {
			return err
		}
		pcrs += fmt.Sprintf("PCR-%02d: %x\n", i, hash)
	}
	fmt.Print(pcrs)

	return nil
}

// PcrRead reads the value of a PCR
func PcrRead() error {
	if *pcrCommandReadIndex >= MaxPlatformConfigurationRegister || *pcrCommandReadIndex < 0 {
		return errors.New("PCR index is incorrect")
	}

	pcr, err := TPMInterface.ReadPCR(*pcrCommandReadIndex)
	if err != nil {
		return err
	}

	fmt.Printf("PCR-%02d: %x\n", *pcrCommandReadIndex, pcr)

	return nil
}

// PcrMeasure measures a file into a defined PCR
func PcrMeasure() error {
	if *pcrCommandMeasureIndex >= MaxPlatformConfigurationRegister || *pcrCommandMeasureIndex < 0 {
		return errors.New("PCR index is incorrect")
	}

	fileToMeasure, err := ioutil.ReadFile(*pcrCommandMeasureFile)
	if err != nil {
		return err
	}

	err = TPMInterface.Measure(*pcrCommandMeasureIndex, fileToMeasure)
	if err != nil {
		return err
	}

	return nil
}

// DiskFormat formats a device for luks setup.
func DiskFormat() error {
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

	err = CryptsetupFormat(keystorePath+"/plain", *diskCommandFormatDevice)
	if err != nil {
		return err
	}

	sealed, err := TPMInterface.SealData(*diskCommandFormatLocality, *diskCommandFormatPcrs, randBytes, *diskCommandSrkPassword)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(*diskCommandFormatFile, sealed, 660); err != nil {
		return err
	}

	return UnmountKeystore(keystorePath)
}

// DiskOpen opens a LUKS device
func DiskOpen() error {
	keystorePath, err := MountKeystore()
	if err != nil {
		return err
	}

	if _, err = os.Stat(*diskCommandOpenMountPath); os.IsNotExist(err) {
		return err
	}

	sealedFile, err := ioutil.ReadFile(*diskCommandOpenSealFile)
	if err != nil {
		return err
	}

	sealed, err := TPMInterface.UnsealData(sealedFile, *diskCommandSrkPassword)
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

// DiskClose closes a LUKS device
func DiskClose() error {
	deviceMapperPath := path.Join("/dev/mapper/", *diskCommandCloseName)
	mountpoint, err := storage.GetMountpointByDevice(deviceMapperPath)
	if err != nil {
		return err
	}

	syscall.Unmount(*mountpoint, syscall.MNT_DETACH|syscall.MNT_FORCE)
	return CryptsetupClose(*diskCommandCloseName)
}

// DiskExtend hashes and extends a LUKS header into a PCR
func DiskExtend() error {
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

	return TPMInterface.Measure(*diskCommandExtendPcr, luksHeader)
}

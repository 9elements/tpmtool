package main

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"syscall"

	tspi "github.com/google/go-tpm/tpm"
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
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

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

	return nil
}

// Ek dumps the Endorsement Key
func Ek() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	var pubEk []byte
	pubEk, err = tpmInterface.ReadPubEK(*ekCommandPassword)
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
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	err = tpmInterface.TakeOwnership(*ownerCommandPassword, *ownerCommandTakeSrkPassword)
	if err != nil {
		return err
	}

	return nil
}

// OwnerClear clears ownership of the TPM
func OwnerClear() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	err = tpmInterface.ClearOwnership(*ownerCommandPassword)
	if err != nil {
		return err
	}

	return nil
}

// OwnerResetLock resets the TPM bruteforce lock
func OwnerResetLock() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	err = tpmInterface.ResetLock(*ownerCommandPassword)
	if err != nil {
		return err
	}

	return nil
}

// CryptoSeal seals data aganst PCR with TPM
func CryptoSeal() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

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

	return ioutil.WriteFile(*cryptoCommandSealCipherFile, sealed, 660)
}

// CryptoUnseal unseals data by the TPM against PCR
func CryptoUnseal() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	cipherText, err := ioutil.ReadFile(*cryptoCommandUnsealCipherFile)
	if err != nil {
		return err
	}

	unsealed, err := tpmInterface.UnsealData(cipherText, *cryptoCommandSrkPassword)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(*cryptoCommandUnsealPlainFile, unsealed, 660)
}

// CryptoReseal reseals a data by given sealing configuration
func CryptoReseal() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	if !filepath.IsAbs(*cryptoCommandResealConfig) {
		return err
	}

	if !filepath.IsAbs(*cryptoCommandResealKeyfile) {
		return err
	}

	sealedFile, err := ioutil.ReadFile(*cryptoCommandResealKeyfile)
	if err != nil {
		return err
	}

	pcrInfo, err := PreCalculate(*cryptoCommandResealConfig)
	if err != nil {
		return nil
	}

	unsealed, err := tpmInterface.UnsealData(sealedFile, *diskCommandSrkPassword)
	if err != nil {
		return err
	}

	sealed, err := resealData(*cryptoCommandResealLocality, pcrInfo, unsealed, *cryptoCommandSrkPassword)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(*cryptoCommandResealKeyfile, sealed, 660)
}

// PcrList dumps all PCRs
func PcrList() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	var pcrs string
	for i := uint32(0); i < MaxPlatformConfigurationRegister; i++ {
		hash, err := tpmInterface.ReadPCR(i)
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
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	if *pcrCommandReadIndex >= MaxPlatformConfigurationRegister || *pcrCommandReadIndex < 0 {
		return errors.New("PCR index is incorrect")
	}

	pcr, err := tpmInterface.ReadPCR(*pcrCommandReadIndex)
	if err != nil {
		return err
	}

	fmt.Printf("PCR-%02d: %x\n", *pcrCommandReadIndex, pcr)

	return nil
}

// PcrMeasure measures a file into a defined PCR
func PcrMeasure() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

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

	return nil
}

// DiskFormat formats a device for luks setup.
func DiskFormat() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

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

	sealed, err := tpmInterface.SealData(*diskCommandFormatLocality, *diskCommandFormatPcrs, randBytes, *diskCommandSrkPassword)
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

// DiskOpen opens a LUKS device
func DiskOpen() error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

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

	if _, err = os.Stat(*diskCommandOpenMountPath); os.IsNotExist(err) {
		return err
	}

	sealedFile, err := ioutil.ReadFile(*diskCommandOpenSealFile)
	if err != nil {
		return err
	}

	sealed, err := tpmInterface.UnsealData(sealedFile, *diskCommandSrkPassword)
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
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

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

func resealData(locality byte, pcrInfo map[int][]byte, data []byte, srkPassword string) ([]byte, error) {
	var srkAuth [20]byte
	if srkPassword != "" {
		srkAuth = sha1.Sum([]byte(srkPassword))
	}

	rwc, err := tpm.TPMOpener(tpm.TPMDevice)
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	sealed, err := tspi.Reseal(rwc, locality, pcrInfo, data, srkAuth[:])
	if err != nil {
		return nil, err
	}

	return sealed, nil
}

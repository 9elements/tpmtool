package main

import (
	"crypto/sha1"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/koding/multiconfig"
	"github.com/systemboot/systemboot/pkg/tpm"
)

// CurrentPCRMap is the current used PCR map and a copy of the default map
var CurrentPCRMap map[int][]byte

// TPM1DefaultPCRMap is the TPM 1.2 default PCR map after a power cycle without
// any measurements done
var TPM1DefaultPCRMap = map[int][]byte{
	0:  make([]byte, 20),
	1:  make([]byte, 20),
	2:  make([]byte, 20),
	3:  make([]byte, 20),
	4:  make([]byte, 20),
	5:  make([]byte, 20),
	6:  make([]byte, 20),
	7:  make([]byte, 20),
	8:  make([]byte, 20),
	9:  make([]byte, 20),
	10: make([]byte, 20),
	11: make([]byte, 20),
	12: make([]byte, 20),
	13: make([]byte, 20),
	14: make([]byte, 20),
	15: make([]byte, 20),
	16: make([]byte, 20),
	17: []byte{'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f'},
	18: []byte{'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f'},
	19: []byte{'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f'},
	20: []byte{'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f'},
	21: []byte{'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f'},
	22: []byte{'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f'},
	23: make([]byte, 20),
}

func hashSum(data []byte) ([]byte, error) {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return nil, err
	}
	defer tpmInterface.Close()

	if tpmInterface.Info().Specification == tpm.TPM12 {
		hash := sha1.Sum(data)
		return hash[:], nil
	}

	return nil, errors.New("TPM spec not implemented yet")
}

// StaticPCR populates a static PCR into the map
func StaticPCR(pcrIndex int, hash []byte) {
	CurrentPCRMap[pcrIndex] = hash
}

// DynamicPCR gets the current PCR and populates it into the map
func DynamicPCR(pcrIndex int) error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	hash, err := tpmInterface.ReadPCR(uint32(pcrIndex))
	if err != nil {
		return err
	}

	CurrentPCRMap[pcrIndex] = hash
	return nil
}

// ExtendPCR extends a hash into a current PCR
func ExtendPCR(pcrIndex int, hash []byte) error {
	hash, err := hashSum(append(CurrentPCRMap[pcrIndex], hash...))
	if err != nil {
		return err
	}

	CurrentPCRMap[pcrIndex] = hash
	return nil
}

// MeasurePCR measures a file into a PCR
func MeasurePCR(pcrIndex int, filePath string) error {
	if !filepath.IsAbs(filePath) {
		return errors.New("File path not absolute")
	}

	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var fileHash []byte
	fileHash, err = hashSum(file)
	if err != nil {
		return err
	}

	hash, err := hashSum(append(CurrentPCRMap[pcrIndex], fileHash...))
	if err != nil {
		return err
	}

	CurrentPCRMap[pcrIndex] = hash
	return nil
}

// LuksPCR extends the hash of a LUKS device into a current PCR
func LuksPCR(pcrIndex int, devicePath string) error {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return err
	}
	defer tpmInterface.Close()

	if !filepath.IsAbs(devicePath) {
		return err
	}

	deviceFD, err := os.Open(devicePath)
	if err != nil {
		return err
	}
	defer deviceFD.Close()

	luksHeader := make([]byte, Luks1HeaderLength)
	_, err = deviceFD.Read(luksHeader)
	if err != nil {
		return err
	}

	hash, err := hashSum(append(CurrentPCRMap[pcrIndex], luksHeader...))
	if err != nil {
		return err
	}

	CurrentPCRMap[pcrIndex] = hash
	return nil
}

func runCalculations(calculations []PreCalculation, pcrIndex int) error {
	for _, calculation := range calculations {
		if calculation.Method == Static && len(calculations) > 1 {
			return errors.New("Static type: More calculation defined than possible")
		}

		if calculation.Method == Dynamic && len(calculations) > 1 {
			return errors.New("Dynamic type: More calculation defined than possible")
		}
	}

	for _, calculation := range calculations {
		switch calculation.Method {
		case Static:
			hash := calculation.Hash
			if hash == "" {
				return errors.New("Static type: No hash defined")
			}
			StaticPCR(pcrIndex, []byte(hash))
		case Dynamic:
			return DynamicPCR(pcrIndex)
		case Extend:
			if len(calculation.Hashes) <= 0 {
				return errors.New("Extend type: No hashes defined")
			}
			for _, hash := range calculation.Hashes {
				return ExtendPCR(pcrIndex, []byte(hash))
			}
		case Measure:
			if len(calculation.FilePaths) <= 0 {
				return errors.New("Measure type: No paths defined")
			}
			for _, path := range calculation.FilePaths {
				return MeasurePCR(pcrIndex, path)
			}
		case Luks:
			if calculation.DevicePath == "" {
				return errors.New("Luks type: No path defined")
			}
			return LuksPCR(pcrIndex, calculation.DevicePath)
		default:
			return errors.New(string(calculation.Method) + " not implemented")
		}
	}

	return nil
}

func executeConfig(sealingConfig *TPM1SealingConfig) error {
	if sealingConfig.Pcr0 != nil {
		return runCalculations(sealingConfig.Pcr0, 0)
	}

	if sealingConfig.Pcr1 != nil {
		return runCalculations(sealingConfig.Pcr1, 1)
	}

	if sealingConfig.Pcr2 != nil {
		return runCalculations(sealingConfig.Pcr2, 2)
	}

	if sealingConfig.Pcr3 != nil {
		return runCalculations(sealingConfig.Pcr3, 3)
	}

	if sealingConfig.Pcr4 != nil {
		return runCalculations(sealingConfig.Pcr4, 4)
	}

	if sealingConfig.Pcr5 != nil {
		return runCalculations(sealingConfig.Pcr5, 5)
	}

	if sealingConfig.Pcr6 != nil {
		return runCalculations(sealingConfig.Pcr6, 6)
	}

	if sealingConfig.Pcr7 != nil {
		return runCalculations(sealingConfig.Pcr7, 7)
	}

	if sealingConfig.Pcr8 != nil {
		return runCalculations(sealingConfig.Pcr8, 8)
	}

	if sealingConfig.Pcr9 != nil {
		return runCalculations(sealingConfig.Pcr9, 9)
	}

	if sealingConfig.Pcr10 != nil {
		return runCalculations(sealingConfig.Pcr10, 10)
	}

	if sealingConfig.Pcr11 != nil {
		return runCalculations(sealingConfig.Pcr11, 11)
	}

	if sealingConfig.Pcr12 != nil {
		return runCalculations(sealingConfig.Pcr12, 12)
	}

	if sealingConfig.Pcr13 != nil {
		return runCalculations(sealingConfig.Pcr13, 13)
	}

	if sealingConfig.Pcr14 != nil {
		return runCalculations(sealingConfig.Pcr14, 14)
	}

	if sealingConfig.Pcr15 != nil {
		return runCalculations(sealingConfig.Pcr15, 15)
	}

	if sealingConfig.Pcr16 != nil {
		return runCalculations(sealingConfig.Pcr16, 16)
	}

	if sealingConfig.Pcr17 != nil {
		return runCalculations(sealingConfig.Pcr17, 17)
	}

	if sealingConfig.Pcr18 != nil {
		return runCalculations(sealingConfig.Pcr18, 18)
	}

	if sealingConfig.Pcr19 != nil {
		return runCalculations(sealingConfig.Pcr19, 19)
	}

	if sealingConfig.Pcr20 != nil {
		return runCalculations(sealingConfig.Pcr20, 20)
	}

	if sealingConfig.Pcr21 != nil {
		return runCalculations(sealingConfig.Pcr21, 21)
	}

	if sealingConfig.Pcr22 != nil {
		return runCalculations(sealingConfig.Pcr22, 22)
	}

	if sealingConfig.Pcr23 != nil {
		return runCalculations(sealingConfig.Pcr23, 23)
	}

	return nil
}

// PreCalculate calculates a PCR map by a given sealing configuration
// doing different types of calculations in the right order
func PreCalculate(sealingConfigPath string) (map[int][]byte, error) {
	tpmInterface, err := tpm.NewTPM()
	if err != nil {
		return nil, err
	}
	defer tpmInterface.Close()

	// Initialize the default values
	var sealingConf *TPM1SealingConfig
	if tpmInterface.Info().Specification == tpm.TPM12 {
		CurrentPCRMap = TPM1DefaultPCRMap
		sealingConf = new(TPM1SealingConfig)
	} else {
		return nil, errors.New("TPM spec not implemented yet")
	}

	config := multiconfig.NewWithPath(sealingConfigPath)
	if config == nil {
		return nil, errors.New("Couldn't load config from disk")
	}

	if err := config.Load(sealingConf); err != nil {
		return nil, err
	}

	if err := executeConfig(sealingConf); err != nil {
		return nil, err
	}

	return CurrentPCRMap, nil
}

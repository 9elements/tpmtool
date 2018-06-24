package main

import (
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/systemboot/systemboot/pkg/tpm"
)

/*
[1] TCG EFI Platform Specification For TPM Family 1.1 or 1.2
https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf

[2] TCG PC Client Specific Implementation Specification for Conventional BIOS", version 1.21
https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf

[3] TCG EFI Protocol Specification, Family "2.0"
https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf

[4] TCG PC Client Platform Firmware Profile Specification
https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
*/
var (
	// DefaultTCPABinaryLog log file where the TCPA log is stored
	DefaultTCPABinaryLog = "/sys/kernel/security/tpm0/binary_bios_measurements"
)

// HashAlgoToSize is a map converter for hash to length
var HashAlgoToSize = map[TPMIAlgHash]TPMIAlgHashSize{
	TPMAlgSha:     TPMAlgShaSize,
	TPMAlgSha256:  TPMAlgSha256Size,
	TPMAlgSha384:  TPMAlgSha384Size,
	TPMAlgSha512:  TPMAlgSha512Size,
	TPMAlgSm3s256: TPMAlgSm3s256Size,
}

// TPMIHA is a TPM2 structure
type TPMIHA struct {
	hash []byte
}

// TPMTHA is a TPM2 structure
type TPMTHA struct {
	hashAlg TPMIAlgHash
	digest  TPMIHA
}

// TPMLDigestValues is a TPM2 structure
type TPMLDigestValues struct {
	count   uint32
	digests []TPMTHA
}

// TcgEfiSpecIDEventAlgorithmSize is a TPM2 structure
type TcgEfiSpecIDEventAlgorithmSize struct {
	algorithID uint16
	digestSize uint16
}

// TcgEfiSpecIDEvent is a TPM2 structure
type TcgEfiSpecIDEvent struct {
	signature          [16]byte
	platformClass      uint32
	specVersionMinor   uint8
	specVersionMajor   uint8
	specErrata         uint8
	uintnSize          uint8
	numberOfAlgorithms uint32
	digestSizes        []TcgEfiSpecIDEventAlgorithmSize
	vendorInfoSize     uint8
	vendorInfo         []byte
}

// TcgBiosSpecIDEvent is a TPM2 structure
type TcgBiosSpecIDEvent struct {
	signature        [16]byte
	platformClass    uint32
	specVersionMinor uint8
	specVersionMajor uint8
	specErrata       uint8
	uintnSize        uint8
	vendorInfoSize   uint8
	vendorInfo       []byte
}

// TcgPcrEvent2 is a TPM2 default log structure (EFI only)
type TcgPcrEvent2 struct {
	pcrIndex  uint32
	eventType uint32
	digests   TPMLDigestValues
	eventSize uint32
	event     TcgEfiSpecIDEvent
}

// TcgPcrEvent is the TPM1.2 default log structure (BIOS, EFI compatible)
type TcgPcrEvent struct {
	pcrIndex  uint32
	eventType uint32
	digest    [20]byte
	eventSize uint32
	event     TcgBiosSpecIDEvent
}

// PCRDigestValue is the hash and algorithm
type PCRDigestValue struct {
	digestAlg TPMIAlgHash
	digest    []byte
}

// PCRDigestInfo is the info about the measurements
type PCRDigestInfo struct {
	pcrIndex     int
	pcrEventName string
	digestCount  uint32
	digests      []PCRDigestValue
}

// PCRLog is a generic PCR eventlog structure
type PCRLog struct {
	firmware FirmwareType
	pcrList  []PCRDigestInfo
}

func readTPM2Log(firmware FirmwareType) (*PCRLog, error) {
	var pcrLog PCRLog
	pcrLog.firmware = firmware

	file, err := os.Open(DefaultTCPABinaryLog)
	if err != nil {
		return nil, err
	}

	var endianess binary.ByteOrder = binary.LittleEndian
	var pcrDigest PCRDigestInfo
	var pcrEvent TcgPcrEvent2
	for {
		if err := binary.Read(file, endianess, &pcrEvent.pcrIndex); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, endianess, &pcrEvent.eventType); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, endianess, &pcrEvent.digests.count); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		pcrEvent.digests.digests = make([]TPMTHA, pcrEvent.digests.count)
		for i := uint32(0); i < pcrEvent.digests.count; i++ {
			if err := binary.Read(file, endianess, &pcrEvent.digests.digests[i].hashAlg); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			pcrEvent.digests.digests[i].digest.hash = make([]byte, HashAlgoToSize[pcrEvent.digests.digests[i].hashAlg])
			if err := binary.Read(file, endianess, &pcrEvent.digests.digests[i].digest.hash); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}
		}

		if err := binary.Read(file, endianess, &pcrEvent.eventSize); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		if BIOSLogID(pcrEvent.eventType) == EvNoAction {
			if err := binary.Read(file, endianess, pcrEvent.event.signature); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if string(pcrEvent.event.signature[:]) != TCGAgileEventFormatID {
				continue
			}

			// TODO implement hash parsing in EV_NO_ACTION case
			pcrDigest.digestCount = 1
			pcrDigest.digests = make([]PCRDigestValue, 1)
			pcrDigest.digests[0].digestAlg = TPMAlgSha
			pcrDigest.pcrEventName = ""
			pcrDigest.pcrIndex = int(pcrEvent.pcrIndex)
			pcrLog.pcrList = append(pcrLog.pcrList, pcrDigest)
		} else {
			// Placeholder
			if err := binary.Read(file, endianess, make([]byte, pcrEvent.eventSize)); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			pcrDigest.digestCount = pcrEvent.digests.count
			pcrDigest.digests = make([]PCRDigestValue, pcrEvent.digests.count)
			for i := uint32(0); i < pcrEvent.digests.count; i++ {
				pcrDigest.digests[i].digestAlg = TPMAlgSha
				pcrDigest.digests[i].digest = make([]byte, pcrEvent.digests.digests[i].hashAlg)
				copy(pcrDigest.digests[i].digest, pcrEvent.digests.digests[i].digest.hash)
			}

			if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
				pcrDigest.pcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
			}
			if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
				pcrDigest.pcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
			}

			pcrDigest.pcrIndex = int(pcrEvent.pcrIndex)
			pcrLog.pcrList = append(pcrLog.pcrList, pcrDigest)
		}
	}
	file.Close()

	return &pcrLog, nil
}

func readTPM1Log(firmware FirmwareType) (*PCRLog, error) {
	var pcrLog PCRLog
	pcrLog.firmware = firmware

	file, err := os.Open(DefaultTCPABinaryLog)
	if err != nil {
		return nil, err
	}

	var endianess binary.ByteOrder = binary.LittleEndian
	var pcrDigest PCRDigestInfo
	var pcrEvent TcgPcrEvent
	for {
		if err := binary.Read(file, endianess, &pcrEvent.pcrIndex); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, endianess, &pcrEvent.eventType); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, endianess, &pcrEvent.digest); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if err := binary.Read(file, endianess, &pcrEvent.eventSize); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		pcrDigest.digestCount = 1
		pcrDigest.digests = make([]PCRDigestValue, 1)
		pcrDigest.digests[0].digestAlg = TPMAlgSha
		if BIOSLogID(pcrEvent.eventType) == EvNoAction {
			if err := binary.Read(file, endianess, pcrEvent.event.signature); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if string(pcrEvent.event.signature[:]) != TCGOldEfiFormatID {
				continue
			}

			pcrDigest.pcrEventName = ""
			pcrDigest.pcrIndex = int(pcrEvent.pcrIndex)
			pcrLog.pcrList = append(pcrLog.pcrList, pcrDigest)
		} else {
			// Placeholder
			if err := binary.Read(file, endianess, make([]byte, pcrEvent.eventSize)); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			pcrDigest.digests[0].digest = make([]byte, TPMAlgShaSize)
			copy(pcrDigest.digests[0].digest, pcrEvent.digest[:])

			if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
				pcrDigest.pcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
			}
			if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
				pcrDigest.pcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
			}

			pcrDigest.pcrIndex = int(pcrEvent.pcrIndex)
			pcrLog.pcrList = append(pcrLog.pcrList, pcrDigest)
		}
	}
	file.Close()

	return &pcrLog, nil
}

// ParseLog is a ,..
func ParseLog(firmware FirmwareType) (*PCRLog, error) {
	var pcrLog *PCRLog
	var err error

	switch firmware {
	case Uefi:
	case Bios:
	default:
		return nil, errors.New("Firmware not supported yet")
	}

	switch TPMSpecVersion {
	case tpm.TPM12:
		pcrLog, err = readTPM1Log(firmware)
		if err != nil {
			return nil, err
		}
	case tpm.TPM20:
		pcrLog, err = readTPM2Log(firmware)
		if err != nil {
			// Kernel eventlog workaround does not export agile measurement log..
			pcrLog, err = readTPM1Log(firmware)
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("No valid TPM specification found")
	}

	return pcrLog, nil
}

package tpmtool

import (
	"bytes"
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
	DigestAlg TPMIAlgHash
	Digest    []byte
}

// PCRDigestInfo is the info about the measurements
type PCRDigestInfo struct {
	PcrIndex     int
	PcrEventName string
	Digests      []PCRDigestValue
}

// PCRLog is a generic PCR eventlog structure
type PCRLog struct {
	Firmware FirmwareType
	PcrList  []PCRDigestInfo
}

func readTPM2Log(firmware FirmwareType) (*PCRLog, error) {
	var pcrLog PCRLog
	pcrLog.Firmware = firmware

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

		if BIOSLogID(pcrEvent.eventType) == EvNoAction {
			if err := binary.Read(file, endianess, make([]byte, TPMAlgShaSize)); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.eventSize); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.signature); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			identifier := string(bytes.Trim(pcrEvent.event.signature[:], "\x00"))
			if string(identifier) != TCGAgileEventFormatID {
				continue
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.platformClass); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.specVersionMinor); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.specVersionMajor); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.specErrata); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.uintnSize); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.numberOfAlgorithms); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			pcrEvent.event.digestSizes = make([]TcgEfiSpecIDEventAlgorithmSize, pcrEvent.event.numberOfAlgorithms)
			for i := uint32(0); i < pcrEvent.event.numberOfAlgorithms; i++ {
				if err := binary.Read(file, endianess, &pcrEvent.event.digestSizes[i].algorithID); err == io.EOF {
					break
				} else if err != nil {
					return nil, err
				}
				if err := binary.Read(file, endianess, &pcrEvent.event.digestSizes[i].digestSize); err == io.EOF {
					break
				} else if err != nil {
					return nil, err
				}
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.vendorInfoSize); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			pcrEvent.event.vendorInfo = make([]byte, pcrEvent.event.vendorInfoSize)
			if err := binary.Read(file, endianess, &pcrEvent.event.vendorInfo); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
			}
			if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
			}

			pcrDigest.PcrIndex = int(pcrEvent.pcrIndex)
			pcrLog.PcrList = append(pcrLog.PcrList, pcrDigest)
		} else {
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

			// Placeholder
			if err := binary.Read(file, endianess, make([]byte, pcrEvent.eventSize)); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			pcrDigest.Digests = make([]PCRDigestValue, pcrEvent.digests.count)
			for i := uint32(0); i < pcrEvent.digests.count; i++ {
				pcrDigest.Digests[i].DigestAlg = pcrEvent.digests.digests[i].hashAlg
				pcrDigest.Digests[i].Digest = make([]byte, HashAlgoToSize[pcrEvent.digests.digests[i].hashAlg])
				copy(pcrDigest.Digests[i].Digest, pcrEvent.digests.digests[i].digest.hash)
			}

			if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
			}
			if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
			}

			pcrDigest.PcrIndex = int(pcrEvent.pcrIndex)
			pcrLog.PcrList = append(pcrLog.PcrList, pcrDigest)
		}
	}
	file.Close()

	return &pcrLog, nil
}

func readTPM1Log(firmware FirmwareType) (*PCRLog, error) {
	var pcrLog PCRLog
	pcrLog.Firmware = firmware

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

		pcrDigest.Digests = make([]PCRDigestValue, 1)
		pcrDigest.Digests[0].DigestAlg = TPMAlgSha
		if BIOSLogID(pcrEvent.eventType) == EvNoAction {
			if err := binary.Read(file, endianess, make([]byte, TPMAlgShaSize)); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.eventSize); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.signature); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			identifier := string(bytes.Trim(pcrEvent.event.signature[:], "\x00"))
			if string(identifier) != TCGOldEfiFormatID {
				continue
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.platformClass); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.specVersionMinor); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.specVersionMajor); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.specErrata); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.uintnSize); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if err := binary.Read(file, endianess, &pcrEvent.event.vendorInfoSize); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			pcrEvent.event.vendorInfo = make([]byte, pcrEvent.event.vendorInfoSize)
			if err := binary.Read(file, endianess, &pcrEvent.event.vendorInfo); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
			}
			if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
			}

			pcrDigest.PcrIndex = int(pcrEvent.pcrIndex)
			pcrLog.PcrList = append(pcrLog.PcrList, pcrDigest)
		} else {
			// Placeholder
			if err := binary.Read(file, endianess, make([]byte, pcrEvent.eventSize)); err == io.EOF {
				break
			} else if err != nil {
				return nil, err
			}

			pcrDigest.Digests[0].Digest = make([]byte, TPMAlgShaSize)
			copy(pcrDigest.Digests[0].Digest, pcrEvent.digest[:])

			if BIOSLogTypes[BIOSLogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = BIOSLogTypes[BIOSLogID(pcrEvent.eventType)]
			}
			if EFILogTypes[EFILogID(pcrEvent.eventType)] != "" {
				pcrDigest.PcrEventName = EFILogTypes[EFILogID(pcrEvent.eventType)]
			}

			pcrDigest.PcrIndex = int(pcrEvent.pcrIndex)
			pcrLog.PcrList = append(pcrLog.PcrList, pcrDigest)
		}
	}
	file.Close()

	return &pcrLog, nil
}

// ParseLog is a ,..
func ParseLog(firmware FirmwareType, tpmSpec string) (*PCRLog, error) {
	var pcrLog *PCRLog
	var err error

	switch firmware {
	case Uefi:
	case Bios:
	default:
		return nil, errors.New("Firmware not supported yet")
	}

	switch tpmSpec {
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

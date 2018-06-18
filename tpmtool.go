package main

import (
	"log"
	"os"

	//"github.com/awnumar/memguard"
	//"github.com/howeyc/gopass"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	Version  = "0.1"
	Author   = "Philipp Deppenwiese"
	HelpText = "Pure go written TPM tool"
)

var (
	// TPMDevice which should be used
	TPMDevice = kingpin.Flag("device", "TPM device path").File()

	// CommandLine Arguments
	status = kingpin.Command("status", "Show TPM status")

	ekCommand         = kingpin.Command("ek", "TPM EK operations")
	ekCommandPassword = ekCommand.Flag("owner-pass", "TPM owner password").String()
	ekCommandOutfile  = ekCommand.Arg("outfile", "File path to write EK").String()

	ownerCommand         = kingpin.Command("owner", "Manage the TPM")
	ownerCommandPassword = ownerCommand.Flag("owner-pass", "TPM owner password").String()

	ownerCommandTake            = ownerCommand.Command("take", "Take ownership of the TPM")
	ownerCommandTakeSrkPassword = ownerCommandTake.Flag("srk-pass", "TPM SRK password").String()

	ownerCommandClear = ownerCommand.Command("clear", "Clear ownership of the TPM")

	ownerCommandResetLock = ownerCommand.Command("reset-lock", "Reset the TPM lock")

	cryptoCommand               = kingpin.Command("crypto", "Manage TPM data encryption")
	cryptoCommandSrkPassword    = cryptoCommand.Flag("srk-pass", "TPM SRK password").String()
	cryptoCommandSealPlainFile  = cryptoCommandSeal.Arg("plain-file", "Plain text data file path").Required().String()
	cryptoCommandSealCipherFile = cryptoCommandSeal.Arg("sealed-file", "Encrypted data file path").Required().String()

	cryptoCommandSeal         = cryptoCommand.Command("seal", "Seal data against the TPM")
	cryptoCommandSealPcrs     = cryptoCommandSeal.Flag("pcr", "Set the PCRS for the sealing operation").Required().Ints()
	cryptoCommandSealLocality = cryptoCommandSeal.Flag("locality", "Sets the locality for the sealing operation").Uint8()

	cryptoCommandUnseal           = cryptoCommand.Command("unseal", "Unseal data against the TPM")
	cryptoCommandUnsealCipherFile = cryptoCommandUnseal.Arg("sealed-file", "Encrypted data file path").Required().String()
	cryptoCommandUnsealPlainFile  = cryptoCommandUnseal.Arg("plain-file", "Plain text data file path").Required().String()

	pcrCommand = kingpin.Command("pcr", "Manage TPM PCR operations")

	pcrCommandPrint = pcrCommand.Command("list", "Print all PCRs")

	pcrCommandRead      = pcrCommand.Command("read", "Read a specific PCR")
	pcrCommandReadIndex = pcrCommandRead.Flag("pcr", "Set the PCR printing the hash").Required().Uint32()

	pcrCommandMeasure      = pcrCommand.Command("measure", "Measure data into a given PCR")
	pcrCommandMeasureIndex = pcrCommandMeasure.Flag("pcr", "Set the PCR for the measurement operation").Required().Uint32()
	pcrCommandMeasureFile  = pcrCommandMeasure.Arg("measure-file", "Data which should be measured").Required().String()

	diskCommand = kingpin.Command("disk", "Manage cryptsetup sealed devices")

	diskCommandFormat         = diskCommand.Command("format", "Formet cryptsetup partition with sealing")
	diskCommandFormatFile     = diskCommandFormat.Arg("sealed-key-file", "Sealed encryption key").Required().String()
	diskCommandFormatDevice   = diskCommandFormat.Arg("device", "Device which should be encrypted").Required().String()
	diskCommandFormatPcrs     = diskCommandFormat.Flag("pcr", "Set the PCRS for the sealing operation").Required().Ints()
	diskCommandFormatLocality = diskCommandFormat.Flag("locality", "Sets the locality for the sealing operation").Uint8()

	diskCommandOpen          = diskCommand.Command("open", "Open cryptsetup partition with sealed key")
	diskCommandOpenSealFile  = diskCommandOpen.Arg("sealed-key-file", "Sealed encryption key").Required().String()
	diskCommandOpenDevice    = diskCommandOpen.Arg("device", "Device which should be encrypted").Required().String()
	diskCommandOpenMountPath = diskCommandOpen.Arg("mnt-path", "Mount path for mounting unsealed encrypted device").Required().String()

	diskCommandClose     = diskCommand.Command("close", "Close cryptsetup partition")
	diskCommandCloseName = diskCommandClose.Flag("device-name", "cryptsetup device name").Required().String()

	diskCommandExtend       = diskCommand.Command("extend", "Extend luks header into a PCR")
	diskCommandExtendDevice = diskCommandExtend.Arg("device", "Device which should be encrypted").Required().String()
	diskCommandExtendPcr    = diskCommandExtend.Flag("pcr", "Set the PCR for the measurement operation").Required().Uint32()

	diskCommandReseal = diskCommand.Command("reseal", "Reseal sealed cryptsetup partition with new measurements")
)

func main() {
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version(Version).Author(Author)
	kingpin.CommandLine.Help = HelpText

	// Check for root user
	if user := os.Geteuid(); user != 0 {
		log.Panic("Please run this tool as root user")
	}

	switch kingpin.Parse() {
	case "status":
		if err := Status(); err != nil {
			log.Panic(err.Error())
		}
	case "ek":
		if err := Ek(); err != nil {
			log.Panic(err.Error())
		}
	case "owner take":
		if err := OwnerTake(); err != nil {
			log.Panic(err.Error())
		}
	case "owner clear":
		if err := OwnerClear(); err != nil {
			log.Panic(err.Error())
		}
	case "owner reset-lock":
		if err := OwnerResetLock(); err != nil {
			log.Panic(err.Error())
		}
	case "crypto seal":
		if err := CryptoSeal(); err != nil {
			log.Panic(err.Error())
		}
	case "crypto unseal":
		if err := CryptoUnseal(); err != nil {
			log.Panic(err.Error())
		}
	case "pcr list":
		if err := PcrList(); err != nil {
			log.Panic(err.Error())
		}
	case "pcr read":
		if err := PcrRead(); err != nil {
			log.Panic(err.Error())
		}
	case "pcr measure":
		if err := PcrMeasure(); err != nil {
			log.Panic(err.Error())
		}
	case "disk format":
		if err := DiskFormat(); err != nil {
			log.Panic(err.Error())
		}
	case "disk open":
		if err := DiskOpen(); err != nil {
			log.Panic(err.Error())
		}
	case "disk close":
		if err := DiskClose(); err != nil {
			log.Panic(err.Error())
		}
	case "disk extend":
		if err := DiskExtend(); err != nil {
			log.Panic(err.Error())
		}
	case "disk reseal":
		if err := DiskReseal(); err != nil {
			log.Panic(err.Error())
		}
	default:
		log.Fatal("Command not found")
	}
}

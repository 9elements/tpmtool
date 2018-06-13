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

	ownerCommand                = kingpin.Command("owner", "Manage the TPM")
	ownerCommandPassword        = ownerCommand.Flag("owner-pass", "TPM owner password").String()
	ownerCommandTake            = ownerCommand.Command("take", "Take ownership of the TPM")
	ownerCommandTakeSrkPassword = ownerCommandTake.Flag("srk-pass", "TPM SRK password").String()
	ownerCommandClear           = ownerCommand.Command("clear", "Clear ownership of the TPM")
	ownerCommandResetLock       = ownerCommand.Command("reset-lock", "Reset the TPM lock")

	cryptoCommand                 = kingpin.Command("crypto", "Manage TPM data encryption")
	cryptoCommandSrkPassword      = cryptoCommand.Flag("srk-pass", "TPM SRK password").String()
	cryptoCommandSealPlainFile    = cryptoCommandSeal.Arg("plain-file", "Plain text data file path").Required().String()
	cryptoCommandSealCipherFile   = cryptoCommandSeal.Arg("sealed-file", "Encrypted data file path").Required().String()
	cryptoCommandSeal             = cryptoCommand.Command("seal", "Seal data against the TPM")
	cryptoCommandSealPcrs         = cryptoCommandSeal.Flag("pcr", "Set the PCRS for the sealing operation").Required().Ints()
	cryptoCommandSealLocality     = cryptoCommandSeal.Flag("locality", "Sets the locality for the sealing operation").Uint8()
	cryptoCommandUnseal           = cryptoCommand.Command("unseal", "Unseal data against the TPM")
	cryptoCommandUnsealCipherFile = cryptoCommandUnseal.Arg("sealed-file", "Encrypted data file path").Required().String()
	cryptoCommandUnsealPlainFile  = cryptoCommandUnseal.Arg("plain-file", "Plain text data file path").Required().String()

	pcrCommand             = kingpin.Command("pcr", "Manage TPM PCR operations")
	pcrCommandPrint        = pcrCommand.Command("list", "Print all PCRs")
	pcrCommandRead         = pcrCommand.Command("read", "Read a specific PCR")
	pcrCommandReadIndex    = pcrCommandRead.Flag("pcr", "Set the PCR printing the hash").Required().Uint32()
	pcrCommandMeasure      = pcrCommand.Command("measure", "Measure data into a given PCR")
	pcrCommandMeasureIndex = pcrCommandMeasure.Flag("pcr", "Set the PCR for the measurement operation").Required().Uint32()
	pcrCommandMeasureFile  = pcrCommandMeasure.Arg("measure-file", "Data which should be measured").Required().String()

	diskCommand       = kingpin.Command("disk", "Manage cryptsetup sealed devices")
	diskCommandOpen   = diskCommand.Command("open", "Open cryptsetup partition with sealed key")
	diskCommandClose  = diskCommand.Command("close", "Close cryptsetup partition")
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
		if err := ShowStatus(); err != nil {
			log.Panic(err.Error())
		}
	case "ek":
		if err := GetPubEk(); err != nil {
			log.Panic(err.Error())
		}
	case "owner take":
		if err := OwnTPM(); err != nil {
			log.Panic(err.Error())
		}
	case "owner clear":
		if err := ClearTPM(); err != nil {
			log.Panic(err.Error())
		}
	case "owner reset-lock":
		if err := ResetLockTPM(); err != nil {
			log.Panic(err.Error())
		}
	case "crypto seal":
		if err := Seal(); err != nil {
			log.Panic(err.Error())
		}
	case "crypto unseal":
		if err := Unseal(); err != nil {
			log.Panic(err.Error())
		}
	case "pcr list":
		if err := PrintPcr(); err != nil {
			log.Panic(err.Error())
		}
	case "pcr read":
		if err := ReadPcr(); err != nil {
			log.Panic(err.Error())
		}
	case "pcr measure":
		if err := Measure(); err != nil {
			log.Panic(err.Error())
		}
	default:
		log.Fatal("Command not found")
	}
}

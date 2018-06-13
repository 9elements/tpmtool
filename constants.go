package main

// CalculateType defines the calculation action for the PCR
type CalculateType string

const (
	// Static is hash of type byte array
	Static CalculateType = "static"
	// Dynamic is the current lookup of the PCR value
	Dynamic CalculateType = "Dynamic"
	// Extend a hash into a PCR
	Extend CalculateType = "extend"
	// Measure a file into a PCR
	Measure CalculateType = "measure"
	// Firmware which is platform specific
	Firmware CalculateType = "firmware"
	// Bootloader is the payload of the firmware
	Bootloader CalculateType = "bootloader"
	// Luks header of a block device
	Luks CalculateType = "luks"
	// Exclude a PCR from calculation
	Exclude CalculateType = "exclude"
)

// FirmwareType (BIOS)
type FirmwareType int

const (
	// TianoCore is an Open Source UEFI implementation, www.tianocore.org
	TianoCore FirmwareType = 0
	// Coreboot is an Open Source firmware, www.coreboot.org
	Coreboot FirmwareType = 1
	// UBoot is an Open Source firmware, www.denx.de/wiki/U-Boot
	UBoot FirmwareType = 2
	// LinuxBoot is an Open Source firmware based on UEFI and a Linux runtime,
	// www.linuxboot.org
	LinuxBoot FirmwareType = 3
)

// BootloaderType can be any bootloader
type BootloaderType int

const (
	// Systemboot is a LinuxBoot application
	Systemboot BootloaderType = 0
	// Grub2 is the Grand Unified Bootloader
	Grub2 BootloaderType = 1
	// SeaBios is an implementation of a legacy BIOS
	SeaBios BootloaderType = 2
)

// TPMMaxPCRListSize is the maximum number of PCRs for a TPM
const TPMMaxPCRListSize = 24

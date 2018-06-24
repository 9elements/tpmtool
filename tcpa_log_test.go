package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTPM12BiosEventLog(t *testing.T) {
	TPMSpecVersion = "1.2"
	DefaultTCPABinaryLog = "tests/binary_bios_measurements_tpm12_bios"
	_, err := ParseLog(Bios)
	require.NoError(t, err)
}

func TestParseTPM12UefiEventLog(t *testing.T) {
	TPMSpecVersion = "1.2"
	DefaultTCPABinaryLog = "tests/binary_bios_measurements_tpm12_efi"
	_, err := ParseLog(Uefi)
	require.NoError(t, err)
}

func TestParseTPM20UefiNonAgileEventLog(t *testing.T) {
	TPMSpecVersion = "2.0"
	DefaultTCPABinaryLog = "tests/binary_bios_measurements_tpm20_efi_non_agile"
	_, err := ParseLog(Uefi)
	require.NoError(t, err)
}

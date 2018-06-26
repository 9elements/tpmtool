package tpmtool

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/systemboot/systemboot/pkg/tpm"
)

func TestParseTPM12BiosEventLog(t *testing.T) {
	DefaultTCPABinaryLog = "tests/binary_bios_measurements_tpm12_bios"
	_, err := ParseLog(Bios, tpm.TPM12)
	require.NoError(t, err)
}

func TestParseTPM12UefiEventLog(t *testing.T) {
	DefaultTCPABinaryLog = "tests/binary_bios_measurements_tpm12_efi"
	_, err := ParseLog(Uefi, tpm.TPM12)
	require.NoError(t, err)
}

func TestParseTPM20UefiNonAgileEventLog(t *testing.T) {
	DefaultTCPABinaryLog = "tests/binary_bios_measurements_tpm20_efi_non_agile"
	_, err := ParseLog(Uefi, tpm.TPM20)
	require.NoError(t, err)
}

func TestParseTPM20UefiAgileEventLog(t *testing.T) {
	DefaultTCPABinaryLog = "tests/binary_bios_measurements_tpm20_efi_agile"
	_, err := ParseLog(Uefi, tpm.TPM20)
	require.NoError(t, err)
}

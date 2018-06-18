tpmtool is a tool for TPM interaction and disk encryption. It is written in pure Go.

# Basic Features
* Supports TPM 1.2 and 2.0 with [Go TSS](https://github.com/google/go-tpm).
* Higher TPM abstraction layer (TSPI) is implemented in the [systemboot](https://github.com/systemboot/systemboot).
* Written in pure Go.
* TPM states are derived by Linux sysfs.
* Automatic TSS selection based on TPM version.
* __Currently only TSPI for TPM specification 1.2 is available.__

## Core Features
* Shows the TPM status.
```bash
TPM Manufacturer:          STMicroelectronics
TPM spec:                  1.2
TPM owned:                 true
TPM activated:             true
TPM enabled:               true
TPM temporary deactivated: false
```
* Dumps Endorsement Key into a file and shows the fingerprint.
* Takes ownership of the TPM.
* Clears ownership of the TPM.
* Resets TPM lock in case of active bruteforce detection.
* Sealing/Unsealing credentials with custom/current set of PCRs.
* List and read PCRs
* Measures a file into given PCR index.
* Crypsetup:
  * Format device and seal credential.
  * Open device by sealed credential.
  * Close device.
  * Measure device luks header into a given PCR.

# Dependencies

* __cryptsetup__ binary is required for the disk commands.


package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
)

const (
	// CryptsetupBinary name
	CryptsetupBinary = "cryptsetup"
	// DefaultFormatParams is a default cryptsetup secure option list
	DefaultFormatParams = "-c aes-xts-essiv:sha256 -s 512 -y --use-random -q"
	// DefaultKeyPath is the tmpfs directory for storing keys
	DefaultKeyPath = "/tmp/tpmtool"
	// TpmfsFsName is the linux tpmfs fs name
	TpmfsFsName = "tmpfs"
	// DefaultDevMapperPath is the standard Linux device mapper path
	DefaultDevMapperPath = "/dev/mapper/"
)

// MountKeystore mounts the tmpfs key store
func MountKeystore() (string, error) {
	flags := 0
	data := ""

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	target := filepath.Join(DefaultKeyPath, hex.EncodeToString(randBytes))
	if err := os.MkdirAll(target, 0750); err != nil {
		return "", err
	}

	if err := syscall.Mount(TpmfsFsName, target, TpmfsFsName, uintptr(flags), data); err != nil {
		return "", err
	}

	return target, nil
}

// UnmountKeystore unmounts the tpmfs key store
func UnmountKeystore(target string) error {
	syscall.Sync()
	return syscall.Unmount(target, syscall.MNT_FORCE|syscall.MNT_DETACH)
}

// CryptsetupFormat formats a device with LUKS
func CryptsetupFormat(keyPath string, devicePath string) error {
	cryptsetup, err := exec.LookPath(CryptsetupBinary)
	if err != nil {
		return err
	}

	cmd := exec.Command(cryptsetup, DefaultFormatParams, "-d", keyPath, "luksFormat", devicePath)

	return cmd.Run()
}

// CryptsetupOpen opens a LUKS device
func CryptsetupOpen(keyPath string, devicePath string) (string, error) {
	cryptsetup, err := exec.LookPath(CryptsetupBinary)
	if err != nil {
		return "", err
	}

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	deviceName := hex.EncodeToString(randBytes)
	cmd := exec.Command(cryptsetup, "-d", keyPath, "luksOpen", devicePath, deviceName)

	if err := cmd.Run(); err != nil {
		return "", err
	}

	return deviceName, nil
}

// CryptsetupClose closes a LUKS device
func CryptsetupClose(deviceName string) error {
	cryptsetup, err := exec.LookPath(CryptsetupBinary)
	if err != nil {
		return err
	}

	devicePath := path.Join(DefaultDevMapperPath, deviceName)
	cmd := exec.Command(cryptsetup, "luksClose", devicePath)

	return cmd.Run()
}

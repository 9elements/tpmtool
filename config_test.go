package main

import (
	"testing"

	"github.com/koding/multiconfig"
	"github.com/stretchr/testify/require"
)

var testConfig = multiconfig.NewWithPath("tests/sealing.yaml")

func TestConfigUnmarshal(t *testing.T) {
	CurrentPCRMap = TPM1DefaultPCRMap
	sealingConf := new(TPM1SealingConfig)

	err := testConfig.Load(sealingConf)
	require.NoError(t, err)
}

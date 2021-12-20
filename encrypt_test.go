package avtool

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Encrypt_V11(t *testing.T) {
	password := "asdf"
	body := "secret"
	var encrypted string
	var err error
	encrypted, err = Encrypt(body, password, "")
	assert.NoError(t, err)

	var result string
	result, err = Decrypt(encrypted, password)
	assert.NoError(t, err)
	assert.Equal(t, body, result)
}

func Test_Encrypt_V12(t *testing.T) {
	password := "asdf"
	body := "secret"
	var encrypted string
	var err error
	encrypted, err = Encrypt(body, password, "test")
	assert.NoError(t, err)

	var result string
	result, err = Decrypt(encrypted, password)
	assert.NoError(t, err)
	assert.Equal(t, body, result)
}

func Test_encryptV11(t *testing.T) {
	password := "asdf"
	body := "secret"
	var encrypted string
	var err error
	encrypted, err = encryptV11(body, password)
	assert.NoError(t, err)

	var result string
	result, err = Decrypt(encrypted, password)
	assert.NoError(t, err)
	assert.Equal(t, body, result)
}

func Test_encryptV12(t *testing.T) {
	password := "asdf"
	body := "secret"
	vaultID := "label"
	var encrypted string
	var err error
	encrypted, err = encryptV12(body, password, vaultID)
	assert.NoError(t, err)

	var result string
	result, err = Decrypt(encrypted, password)
	assert.NoError(t, err)
	assert.Equal(t, body, result)
}

func Test_checkvaultID(t *testing.T) {
	var err error
	err = checkVaultID("")
	assert.NoError(t, err)

	err = checkVaultID("1-)90$#98klascalkkDADQXASdasd=-=+_+_=-=")
	assert.NoError(t, err)

	err = checkVaultID("a;b")
	assert.Error(t, err)
}

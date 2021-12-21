package avtool

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Encrypt_V11(t *testing.T) {
	password := []byte("asdf")
	body := []byte("secret")
	var encrypted string
	var err error
	encrypted, err = Encrypt(&EncryptOptions{
		Body:     &body,
		Password: &password,
	})
	assert.NoError(t, err)

	var result string
	data := []byte(encrypted)
	result, err = Decrypt(&DecryptOptions{
		Data:     &data,
		Password: &password,
	})
	assert.NoError(t, err)
	assert.Equal(t, string(body), result)
}

func Test_Encrypt_V12(t *testing.T) {
	password := []byte("asdf")
	body := []byte("secret")
	var encrypted string
	var err error
	encrypted, err = Encrypt(&EncryptOptions{
		Body:     &body,
		Password: &password,
		VaultID:  "test",
	})
	assert.NoError(t, err)

	var result string
	data := []byte(encrypted)
	result, err = Decrypt(&DecryptOptions{
		Data:     &data,
		Password: &password,
	})
	assert.NoError(t, err)
	assert.Equal(t, string(body), result)
}

func Test_encryptV11(t *testing.T) {
	password := []byte("asdf")
	body := []byte("secret")
	var encrypted string
	var err error
	encrypted, err = encryptV11(&EncryptOptions{
		Body:     &body,
		Password: &password,
	})
	assert.NoError(t, err)

	var result string
	data := []byte(encrypted)
	result, err = Decrypt(&DecryptOptions{
		Data:     &data,
		Password: &password,
	})
	assert.NoError(t, err)
	assert.Equal(t, string(body), result)
}

func Test_encryptV12(t *testing.T) {
	password := []byte("asdf")
	body := []byte("secret")
	vaultID := "label"
	var encrypted string
	var err error
	encrypted, err = encryptV12(&EncryptOptions{
		Body:     &body,
		Password: &password,
		VaultID:  vaultID,
	})
	assert.NoError(t, err)

	var result string
	data := []byte(encrypted)
	result, err = Decrypt(&DecryptOptions{
		Data:     &data,
		Password: &password,
	})
	assert.NoError(t, err)
	assert.Equal(t, string(body), result)
}

func Test_checkVaultID(t *testing.T) {
	var err error
	err = checkVaultID("")
	assert.NoError(t, err)

	err = checkVaultID("1-)90$#98klascalkkDADQXASdasd=-=+_+_=-=")
	assert.NoError(t, err)

	err = checkVaultID("a;b")
	assert.Error(t, err)
}

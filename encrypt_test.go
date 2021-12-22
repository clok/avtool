package avtool

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
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

func Test_Encrypt_V12_Bad_VaultID(t *testing.T) {
	password := []byte("asdf")
	body := []byte("secret")
	var err error
	_, err = Encrypt(&EncryptOptions{
		Body:     &body,
		Password: &password,
		VaultID:  "A;Bad;Label",
	})
	if assert.Error(t, err) {
		assert.Equal(t, errors.New("vaultID (A;Bad;Label) cannot contain ';'"), err)
	}
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

func Test_EncryptFile_V11(t *testing.T) {
	password := []byte("asdf")
	encrypted, err := EncryptFile(&EncryptFileOptions{
		Filename: "./testdata/encrypt_file.log",
		Password: &password,
	})
	assert.NoError(t, err)
	assert.Contains(t, encrypted, "$ANSIBLE_VAULT;1.1;AES256")

	var result string
	data := []byte(encrypted)
	result, err = Decrypt(&DecryptOptions{
		Data:     &data,
		Password: &password,
	})
	assert.NoError(t, err)

	expected := `This is a test.

I have data.
`
	assert.Equal(t, expected, result)
}

func Test_EncryptFile_V12(t *testing.T) {
	password := []byte("asdf")
	encrypted, err := EncryptFile(&EncryptFileOptions{
		Filename: "./testdata/encrypt_file.log",
		Password: &password,
		VaultID:  "test-label",
	})
	assert.NoError(t, err)
	assert.Contains(t, encrypted, "$ANSIBLE_VAULT;1.2;AES256;test-label")

	var result string
	data := []byte(encrypted)
	result, err = Decrypt(&DecryptOptions{
		Data:     &data,
		Password: &password,
	})
	assert.NoError(t, err)

	expected := `This is a test.

I have data.
`
	assert.Equal(t, expected, result)
}

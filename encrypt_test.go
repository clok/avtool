package avtool

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Encrypt(t *testing.T) {
	password := "asdf"
	body := "secret"
	var encrypted string
	var err error
	encrypted, err = Encrypt(body, password)
	assert.NoError(t, err)

	var result string
	result, err = Decrypt(encrypted, password)
	assert.NoError(t, err)
	assert.Equal(t, body, result)
}

func Test_Encrypt_v2(t *testing.T) {
	password := "asdf"
	body := "secret"
	label := "label"
	var encrypted string
	var err error
	encrypted, err = Encrypt2(body, password, label)
	assert.NoError(t, err)

	var result string
	result, err = Decrypt(encrypted, password)
	assert.NoError(t, err)
	assert.Equal(t, body, result)
}

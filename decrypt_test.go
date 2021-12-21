package avtool

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Decrypt_V11(t *testing.T) {
	password := []byte("asdf")
	content := []byte(`$ANSIBLE_VAULT;1.1;AES256
39663038636438383965366163636163376531336238346239623934393436393938656439643133
3638363066366433666438623138373866393763373265320a366635386630336562633763323236
61616562393964666464653532636436346535616566613434613361303734373734383930323661
6664306264366235630a643235323438646132656337613434396338396335396439346336613062
3766
`)
	result, err := Decrypt(&DecryptOptions{
		Data:     &content,
		Password: &password,
	})
	assert.Equal(t, "hello", result)
	assert.NoError(t, err)
}

func Test_Decrypt_V12(t *testing.T) {
	password := []byte("asdf")
	content := []byte(`$ANSIBLE_VAULT;1.2;AES256;label
39663038636438383965366163636163376531336238346239623934393436393938656439643133
3638363066366433666438623138373866393763373265320a366635386630336562633763323236
61616562393964666464653532636436346535616566613434613361303734373734383930323661
6664306264366235630a643235323438646132656337613434396338396335396439346336613062
3766
`)
	result, err := Decrypt(&DecryptOptions{
		Data:     &content,
		Password: &password,
	})
	assert.Equal(t, "hello", result)
	assert.NoError(t, err)
}

func Test_DecryptFile(t *testing.T) {
	password := []byte("asdf")
	filename := "./testdata/test1/secrets.yaml"
	_, err := DecryptFile(&DecryptFileOptions{
		Filename: filename,
		Password: &password,
	})
	assert.NoError(t, err)
}

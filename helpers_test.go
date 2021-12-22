package avtool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_checkVaultID(t *testing.T) {
	var err error
	err = checkVaultID("")
	assert.NoError(t, err)

	err = checkVaultID("1-)90$#98klascalkkDADQXASdasd=-=+_+_=-=")
	assert.NoError(t, err)

	err = checkVaultID("a;b")
	assert.Error(t, err)
}

func Test_GenerateRandomBytes(t *testing.T) {
	var bytes []byte
	var err error
	bytes, err = GenerateRandomBytes(10)
	assert.NoError(t, err)
	assert.Equal(t, 10, len(bytes))

	bytes, err = GenerateRandomBytes(0)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(bytes))
}

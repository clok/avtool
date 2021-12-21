package avtool

import (
	"fmt"
	"math/rand"
	"strings"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func checkVaultID(vaultID string) error {
	if strings.Contains(vaultID, ";") {
		return fmt.Errorf("vaultID (%s) cannot contain ';'", vaultID)
	}
	return nil
}

// GenerateRandomBytes will generate n length bytes using rand.Read
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}

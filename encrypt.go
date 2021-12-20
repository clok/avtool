package avtool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"strings"
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}

func EncryptFile(filename, password, vaultID string) (result string, err error) {
	data, err := ioutil.ReadFile(filename)
	check(err)
	if vaultID == "" {
		result, err = encryptV11(string(data), password)
	} else {
		result, err = encryptV12(string(data), password, vaultID)
	}
	return
}

// Encrypt will vault encrypt a piece of data.
//
// If a `vaultID` is not an empty string, it will upversion to 1.2, otherwise it will
// default to using 1.1.
//
// `vaultID` must not include `;`. If it does, an error will be thrown.
func Encrypt(body, password, vaultID string) (result string, err error) {
	err = checkVaultID(vaultID)
	if err != nil {
		return "", err
	}
	if vaultID == "" {
		return encryptV11(body, password)
	}
	return encryptV12(body, password, vaultID)
}

func checkVaultID(vaultID string) error {
	if strings.Contains(vaultID, ";") {
		return errors.New("vaultID cannot contain ';'")
	}
	return nil
}

// see https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L710
func encryptV11(body, password string) (result string, err error) {
	salt, err := GenerateRandomBytes(32)
	check(err)
	// salt_64 := "2262970e2309d5da757af6c473b0ed3034209cc0d48a3cc3d648c0b174c22fde"
	// salt,_ = hex.DecodeString(salt_64)
	key1, key2, iv := genKeyInitctr(password, salt)
	ciphertext := createCipherText(body, key1, iv)
	combined := combineParts(ciphertext, key2, salt)
	vaultText := hex.EncodeToString([]byte(combined))
	result = formatOutput(vaultText)
	return
}

// see https://docs.ansible.com/ansible/latest/user_guide/vault.html#ansible-vault-payload-format-1-1-1-2
func Encrypt2(body, password, label string) (result string, err error) {
	salt, err := GenerateRandomBytes(32)
	check(err)
	// salt_64 := "2262970e2309d5da757af6c473b0ed3034209cc0d48a3cc3d648c0b174c22fde"
	// salt,_ = hex.DecodeString(salt_64)
	key1, key2, iv := genKeyInitctr(password, salt)
	ciphertext := createCipherText(body, key1, iv)
	combined := combineParts(ciphertext, key2, salt)
	vaultText := hex.EncodeToString([]byte(combined))
	result = formatOutput2(vaultText, label)
	return
}

// see https://docs.ansible.com/ansible/latest/user_guide/vault.html#ansible-vault-payload-format-1-1-1-2
// see https://github.com/ansible/ansible/blob/0f95371131cd41d97ad95c4e8bd983081eb29a2a/lib/ansible/parsing/vault/__init__.py#L581
func encryptV12(body, password, vaultID string) (result string, err error) {
	salt, err := GenerateRandomBytes(32)
	check(err)
	// salt_64 := "2262970e2309d5da757af6c473b0ed3034209cc0d48a3cc3d648c0b174c22fde"
	// salt,_ = hex.DecodeString(salt_64)
	key1, key2, iv := genKeyInitctr(password, salt)
	ciphertext := createCipherText(body, key1, iv)
	combined := combineParts(ciphertext, key2, salt)
	vaultText := hex.EncodeToString([]byte(combined))
	result = formatOutputV12(vaultText, vaultID)
	return
}

func createCipherText(body string, key1, iv []byte) []byte {
	bs := aes.BlockSize
	padding := (bs - len(body)%bs)
	if padding == 0 {
		padding = bs
	}
	padChar := rune(padding)
	padArray := make([]byte, padding)
	for i := range padArray {
		padArray[i] = byte(padChar)
	}
	plaintext := []byte(body)
	plaintext = append(plaintext, padArray...)

	aesCipher, err := aes.NewCipher(key1)
	check(err)
	ciphertext := make([]byte, len(plaintext))

	aesBlock := cipher.NewCTR(aesCipher, iv)
	aesBlock.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func combineParts(ciphertext, key2, salt []byte) string {
	hmacEncrypt := hmac.New(sha256.New, key2)
	_, err := hmacEncrypt.Write(ciphertext)
	check(err)
	hexSalt := hex.EncodeToString(salt)
	hexHmac := hmacEncrypt.Sum(nil)
	hexCipher := hex.EncodeToString(ciphertext)
	// nolint:unconvert
	combined := string(hexSalt) + "\n" + hex.EncodeToString([]byte(hexHmac)) + "\n" + string(hexCipher)
	return combined
}

func formatOutput(vaultText string) string {
	return formatOutputV11(vaultText)
}

// https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L268
func formatOutputV11(vaultText string) string {
	heading := "$ANSIBLE_VAULT"
	version := "1.1"
	cipherName := "AES256"

	headerElements := make([]string, 3)
	headerElements[0] = heading
	headerElements[1] = version
	headerElements[2] = cipherName
	header := strings.Join(headerElements, ";")

	elements := make([]string, 1)
	elements[0] = header
	for i := 0; i < len(vaultText); i += 80 {
		end := i + 80
		if end > len(vaultText) {
			end = len(vaultText)
		}
		elements = append(elements, vaultText[i:end])
	}
	elements = append(elements, "")

	whole := strings.Join(elements, "\n")
	return whole
}

func formatOutput2(vaultText, labelText string) string {
	heading := "$ANSIBLE_VAULT"
	version := "1.2"
	cipherName := "AES256"

	headerElements := make([]string, 4)
	headerElements[0] = heading
	headerElements[1] = version
	headerElements[2] = cipherName
	headerElements[3] = labelText
	header := strings.Join(headerElements, ";")

	elements := make([]string, 1)
	elements[0] = header
	for i := 0; i < len(vaultText); i += 80 {
		end := i + 80
		if end > len(vaultText) {
			end = len(vaultText)
		}
		elements = append(elements, vaultText[i:end])
	}
	elements = append(elements, "")

	whole := strings.Join(elements, "\n")
	return whole
}

func formatOutputV12(vaultText, vaultIDText string) string {
	heading := "$ANSIBLE_VAULT"
	version := "1.2"
	cipherName := "AES256"

	headerElements := make([]string, 4)
	headerElements[0] = heading
	headerElements[1] = version
	headerElements[2] = cipherName
	headerElements[3] = vaultIDText
	header := strings.Join(headerElements, ";")

	elements := make([]string, 1)
	elements[0] = header
	for i := 0; i < len(vaultText); i += 80 {
		end := i + 80
		if end > len(vaultText) {
			end = len(vaultText)
		}
		elements = append(elements, vaultText[i:end])
	}
	elements = append(elements, "")

	whole := strings.Join(elements, "\n")
	return whole
}

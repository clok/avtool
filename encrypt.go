package avtool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"strings"
)

// EncryptFileOptions is the interface used to pass data to the EncryptFile method
type EncryptFileOptions struct {
	Filename string
	Password *[]byte
	VaultID  string
}

// EncryptFile reads content of filename provided and returns encrypted string
func EncryptFile(opts *EncryptFileOptions) (result string, err error) {
	var data []byte
	data, err = ioutil.ReadFile(opts.Filename)
	if err != nil {
		return "", err
	}
	if opts.VaultID == "" {
		result, err = encryptV11(&EncryptOptions{
			Body:     &data,
			Password: opts.Password,
		})
	} else {
		result, err = encryptV12(&EncryptOptions{
			Body:     &data,
			Password: opts.Password,
			VaultID:  opts.VaultID,
		})
	}
	return
}

// EncryptOptions is the interface used to pass data to the Encrypt method
type EncryptOptions struct {
	Body     *[]byte
	Password *[]byte
	VaultID  string
}

// Encrypt will vault encrypt a piece of data.
//
// If EncryptOptions.VaultID is set, it will upversion to 1.2, otherwise it will
// default to using 1.1.
//
// EncryptOptions.VaultID must not include `;`. If it does, an error will be thrown.
func Encrypt(opts *EncryptOptions) (result string, err error) {
	err = checkVaultID(opts.VaultID)
	if err != nil {
		return "", err
	}
	if opts.VaultID == "" {
		return encryptV11(opts)
	}
	return encryptV12(opts)
}

// encryptData prepares data, encrypts string for formatting
// see https://github.com/ansible/ansible/blob/0f95371131cd41d97ad95c4e8bd983081eb29a2a/lib/ansible/parsing/vault/__init__.py#L581
func encryptData(opts *EncryptOptions) (vaultText string, err error) {
	var salt []byte
	salt, err = GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	// salt_64 := "2262970e2309d5da757af6c473b0ed3034209cc0d48a3cc3d648c0b174c22fde"
	// salt,_ = hex.DecodeString(salt_64)
	key1, key2, iv := genKeyInitctr(opts.Password, salt)

	var cipherText []byte
	cipherText, err = createCipherText(opts.Body, key1, iv)
	if err != nil {
		return "", err
	}

	combined, err := combineParts(cipherText, key2, salt)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString([]byte(combined)), nil
}

// encryptV11 encrypts data and formats the output in Ansible v1.1 vault format
// see https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L710
func encryptV11(opts *EncryptOptions) (result string, err error) {
	var encryptedData string
	encryptedData, err = encryptData(opts)
	if err != nil {
		return "", err
	}
	result = formatOutputV11(encryptedData)
	return
}

// encryptV12 encrypts data and formats the output in Ansible v1.2 vault format
// see https://docs.ansible.com/ansible/latest/user_guide/vault.html#ansible-vault-payload-format-1-1-1-2
// see https://github.com/ansible/ansible/blob/0f95371131cd41d97ad95c4e8bd983081eb29a2a/lib/ansible/parsing/vault/__init__.py#L581
func encryptV12(opts *EncryptOptions) (result string, err error) {
	var encryptedData string
	encryptedData, err = encryptData(opts)
	if err != nil {
		return "", err
	}
	result = formatOutputV12(encryptedData, opts.VaultID)
	return
}

func createCipherText(body *[]byte, key1, iv []byte) ([]byte, error) {
	bs := aes.BlockSize
	padding := bs - len(string(*body))%bs
	if padding == 0 {
		padding = bs
	}
	padChar := rune(padding)
	padArray := make([]byte, padding)
	for i := range padArray {
		padArray[i] = byte(padChar)
	}
	plaintext := *body
	plaintext = append(plaintext, padArray...)

	aesCipher, err := aes.NewCipher(key1)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))

	aesBlock := cipher.NewCTR(aesCipher, iv)
	aesBlock.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func combineParts(ciphertext, key2, salt []byte) (string, error) {
	hmacEncrypt := hmac.New(sha256.New, key2)
	_, err := hmacEncrypt.Write(ciphertext)
	if err != nil {
		return "", err
	}
	hexSalt := hex.EncodeToString(salt)
	hexHmac := hmacEncrypt.Sum(nil)
	hexCipher := hex.EncodeToString(ciphertext)
	// nolint:unconvert
	combined := string(hexSalt) + "\n" + hex.EncodeToString([]byte(hexHmac)) + "\n" + string(hexCipher)
	return combined, nil
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

func formatOutputV12(vaultText, vaultID string) string {
	heading := "$ANSIBLE_VAULT"
	version := "1.2"
	cipherName := "AES256"

	headerElements := make([]string, 4)
	headerElements[0] = heading
	headerElements[1] = version
	headerElements[2] = cipherName
	headerElements[3] = vaultID
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

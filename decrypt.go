package avtool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"strings"
)

// DecryptFileOptions is the interface used to pass data to the DecryptFile method
type DecryptFileOptions struct {
	Filename string
	Password *[]byte
}

// DecryptFile reads content of filename, decrypts it and returns string
func DecryptFile(opts *DecryptFileOptions) (result string, err error) {
	data, err := ioutil.ReadFile(opts.Filename)
	if err != nil {
		return "", err
	}
	result, err = Decrypt(&DecryptOptions{
		Data:     &data,
		Password: opts.Password,
	})
	return
}

// DecryptOptions is the interface used to pass data to the Decrypt method
type DecryptOptions struct {
	Data     *[]byte
	Password *[]byte
}

// Decrypt a string containing the ansible vault
func Decrypt(opts *DecryptOptions) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ERROR: %v", r)
		}
	}()
	data := replaceCarriageReturn(string(*opts.Data))
	body := splitHeader([]byte(data))
	salt, cryptedHmac, ciphertext, err := decodeData(body)
	if err != nil {
		return "", err
	}

	key1, key2, iv := genKeyInitctr(opts.Password, salt)
	err = checkDigest(key2, cryptedHmac, ciphertext)
	if err != nil {
		return "", err
	}

	aesCipher, err := aes.NewCipher(key1)
	if err != nil {
		return "", err
	}

	aesBlock := cipher.NewCTR(aesCipher, iv)
	plaintext := make([]byte, len(ciphertext))
	aesBlock.XORKeyStream(plaintext, ciphertext)
	padding := int(plaintext[len(plaintext)-1])
	result = string(plaintext[:len(plaintext)-padding])
	return
}

// replaceCarriageReturn in order to support vault files with windows line endings
func replaceCarriageReturn(data string) string {
	return strings.ReplaceAll(data, "\r", "")
}

/*
See _split_header function
https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L288
*/
func splitHeader(data []byte) string {
	contents := string(data)
	lines := strings.Split(contents, "\n")
	header := strings.Split(lines[0], ";")
	cipherName := strings.TrimSpace(header[2])
	if cipherName != "AES256" {
		panic(fmt.Errorf("unsupported cipher: %s", cipherName))
	}
	body := strings.Join(lines[1:], "")
	return body
}

/*
See decrypt function (in class VaultAES256)
https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L741
*/
func decodeData(body string) (salt, cryptedHmac, cipherText []byte, err error) {
	decoded, err := hex.DecodeString(body)
	if err != nil {
		return nil, nil, nil, err
	}
	elements := strings.SplitN(string(decoded), "\n", 3)

	salt, err = hex.DecodeString(elements[0])
	if err != nil {
		return nil, nil, nil, err
	}

	cryptedHmac, err = hex.DecodeString(elements[1])
	if err != nil {
		return nil, nil, nil, err
	}

	cipherText, err = hex.DecodeString(elements[2])
	if err != nil {
		return nil, nil, nil, err
	}

	return
}

/*
See function _gen_key_initctr (in class VaultAES256)
https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L685
*/
func genKeyInitctr(password *[]byte, salt []byte) (key1, key2, iv []byte) {
	keyLength := 32
	ivLength := 16
	key := pbkdf2.Key(*password, salt, 10000, 2*keyLength+ivLength, sha256.New)
	key1 = key[:keyLength]
	key2 = key[keyLength:(keyLength * 2)]
	iv = key[(keyLength * 2) : (keyLength*2)+ivLength]
	return
}

/*
See decrypt function (in class VaultAES256)
https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L741
*/
func checkDigest(key2, cryptedHmac, ciphertext []byte) error {
	hmacDecrypt := hmac.New(sha256.New, key2)
	_, err := hmacDecrypt.Write(ciphertext)
	if err != nil {
		return err
	}
	expectedMAC := hmacDecrypt.Sum(nil)
	if !hmac.Equal(cryptedHmac, expectedMAC) {
		return errors.New("digests do not match - exiting")
	}
	return nil
}

package avtool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"log"
	"strings"
)

func check(e error) {
	if e != nil {
		log.Fatalf("error: %v", e)
	}
}

// DecryptFileOptions is the interface used to pass data to the DecryptFile method
type DecryptFileOptions struct {
	Filename string
	Password *[]byte
}

// DecryptFile reads content of filename, decrypts it and returns string
func DecryptFile(opts *DecryptFileOptions) (result string, err error) {
	data, err := ioutil.ReadFile(opts.Filename)
	check(err)
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
	salt, cryptedHmac, ciphertext := decodeData(body)
	key1, key2, iv := genKeyInitctr(string(*opts.Password), salt)
	checkDigest(key2, cryptedHmac, ciphertext)
	aesCipher, err := aes.NewCipher(key1)
	check(err)
	aesBlock := cipher.NewCTR(aesCipher, iv)
	plaintext := make([]byte, len(ciphertext))
	aesBlock.XORKeyStream(plaintext, ciphertext)
	padding := int(plaintext[len(plaintext)-1])
	result = string(plaintext[:len(plaintext)-padding])
	return
}

// in order to support vault files with windows line endings
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
		panic("unsupported cipher: " + cipherName)
	}
	body := strings.Join(lines[1:], "")
	return body
}

/*
See decrypt function (in class VaultAES256)
https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L741
*/
func decodeData(body string) (salt, cryptedHmac, ciphertext []byte) {
	decoded, _ := hex.DecodeString(body)
	elements := strings.SplitN(string(decoded), "\n", 3)
	salt, err1 := hex.DecodeString(elements[0])
	if err1 != nil {
		panic(err1)
	}
	cryptedHmac, err2 := hex.DecodeString(elements[1])
	if err2 != nil {
		panic(err2)
	}
	ciphertext, err3 := hex.DecodeString(elements[2])
	if err3 != nil {
		panic(err3)
	}
	return
}

/*
See function _gen_key_initctr (in class VaultAES256)
https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L685
*/
func genKeyInitctr(password string, salt []byte) (key1, key2, iv []byte) {
	keylength := 32
	ivlength := 16
	key := pbkdf2.Key([]byte(password), salt, 10000, 2*keylength+ivlength, sha256.New)
	key1 = key[:keylength]
	key2 = key[keylength:(keylength * 2)]
	iv = key[(keylength * 2) : (keylength*2)+ivlength]
	return
}

/*
See decrypt function (in class VaultAES256)
https://github.com/ansible/ansible/blob/0b8011436dc7f842b78298848e298f2a57ee8d78/lib/ansible/parsing/vault/__init__.py#L741
*/
func checkDigest(key2, cryptedHmac, ciphertext []byte) {
	hmacDecrypt := hmac.New(sha256.New, key2)
	_, err := hmacDecrypt.Write(ciphertext)
	check(err)
	expectedMAC := hmacDecrypt.Sum(nil)
	if !hmac.Equal(cryptedHmac, expectedMAC) {
		panic("digests do not match - exiting")
	}
}

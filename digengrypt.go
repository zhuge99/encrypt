package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func DE_EncryptGetBase64(key string, data []byte) (string, error) {
	result, err := DE_Encrypt(key, data)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(result), nil
}
func DE_Encrypt(key string, data []byte) ([]byte, error) {
	if key == "" {
		return nil, errors.New("the key is empty")
	}
	datalen := len(data)
	if datalen < 1 {
		return nil, errors.New("data is empty")
	}
	password := adjustPassword(key)
	block, err := aes.NewCipher(password)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+datalen)
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func DE_EncryptFromBase64(key string, data string) ([]byte, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return DE_Decrypt(key, ciphertext)
}
func DE_Decrypt(key string, data []byte) ([]byte, error) {
	if key == "" {
		return nil, errors.New("the key is empty")
	}
	datalen := len(data)
	if datalen < 1 {
		return nil, errors.New("data is empty")
	}
	password := adjustPassword(key)

	block, err := aes.NewCipher(password)
	if err != nil {
		return nil, err
	}

	if datalen < aes.BlockSize {
		return nil, errors.New("data too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(data, data)

	return data, nil
}

func adjustPassword(key string) []byte {
	keytext := key
	for len(keytext) < 16 {
		keytext += key
	}

	if len(keytext) > 32 {
		keytext = keytext[:32]
	} else if len(keytext) > 24 {
		keytext = keytext[:24]
	} else if len(keytext) > 16 {
		keytext = keytext[:16]
	}

	return []byte(keytext)
}

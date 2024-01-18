package encrypt

import (
	"testing"
	"bytes"
	"fmt"
)
var test_password = "test111"
var test_text = "text to encrypt"

func TestEncryptBase64(t *testing.T) {
	got, err := DE_EncryptGetBase64(test_password, []byte(test_text))
	if err != nil {
    	t.Errorf("DE_EncryptGetBase64() error = %v", err)
  	}
	got2, err2 := DE_DecryptFromBase64(test_password, got)
	if err2 != nil {
    	t.Errorf("DE_DecryptFromBase64() error = %v", err)
  	}

    if string(got2) != test_text {
        t.Errorf("DE_EncryptGetBase64 and DE_DecryptFromBase64 wrong: %v", got2)
    } else {
        t.Logf("DE_EncryptGetBase64 and DE_DecryptFromBase64 correct: %v", got2)
		fmt.Println("good1")
	}
}
func TestEncrypt(t *testing.T) {
	got, err := DE_Encrypt(test_password, []byte(test_text))
	if err != nil {
    	t.Errorf("DE_Encrypt() error = %v", err)
  	}
	got2, err2 := DE_Decrypt(test_password, got)
	if err2 != nil {
    	t.Errorf("DE_Decrypt() error = %v", err)
  	}

	if bytes.Compare([]byte(test_text), got2) != 0 {
        t.Errorf("DE_EncryptGet and DE_Decrypt wrong: %v", got2)
    } else {
      t.Logf("DE_EncryptGet and DE_Decrypt correct: %v", got2)
	  fmt.Println("good2")
    }
}

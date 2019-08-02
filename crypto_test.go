//
// go test -v -count 1 -timeout 1h -mod vendor -race -run="RandomNumber|GenerateRandomString" util_test.go
//
package util_test

import (
	"testing"
)

import (
	"github.com/junxie6/util"
)

func TestEncryptAES(t *testing.T) {
	msg := []byte("Hello World")
	secret := "mypass"

	var err error
	var encrypted []byte

	if encrypted, err = util.EncryptAES(msg, secret); err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	var decrypted []byte

	if decrypted, err = util.DecryptAES(encrypted, secret); err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	//fmt.Printf("secret: %v %d\n", encrypted, len(encrypted))
	//fmt.Printf("decrypted: %s %d\n", decrypted, len(decrypted))

	if util.ByteSliceEqual(msg, decrypted) != true {
		t.Errorf("Error: %s", "Decrypted value not match")
		return
	}
}

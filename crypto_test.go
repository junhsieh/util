//
// go test -v -count 1 -timeout 1h -mod vendor -race -run="RandomNumber|GenerateRandomString" util_test.go
//
package util_test

import (
	"crypto/rsa"
	//"fmt"
	"io/ioutil"
	"testing"

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

func TestSignSignature(t *testing.T) {
	var err error
	data := []byte("This is a testing msg")

	//
	var privateKeyBytes []byte

	if privateKeyBytes, err = ioutil.ReadFile("demo.local.key"); err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	//
	var privateKey *rsa.PrivateKey

	if privateKey, err = util.BytesToPrivateKey(privateKeyBytes); err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	//
	var publicKeyBytes []byte

	if publicKeyBytes, err = ioutil.ReadFile("demo.local.pub"); err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	//
	var publicKey *rsa.PublicKey

	if publicKey, err = util.BytesToPublicKey(publicKeyBytes); err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	//
	var signatureBytes []byte

	if signatureBytes, err = util.SignSignature(privateKey, data); err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}

	//
	if err = util.VerifySignature(publicKey, data, signatureBytes); err != nil {
		t.Errorf("Error: %s", err.Error())
		return
	}
}

func TestCreateHash(t *testing.T) {
	//hash := util.CreateHash("asdf")
	//fmt.Printf("HERE: %d %v\n", len(hash), hash)
}

func TestHMACHash(t *testing.T) {
	//hash := util.HMACHash("asdf", "xxx")
	//fmt.Printf("HERE: %d %s\n", len(hash), hash)
}

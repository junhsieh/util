// Reference:
// https://gist.github.com/miguelmota/3ea9286bd1d3c2a985b67cac4ba2130a
// https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key
// https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	var err error
	var privKey *rsa.PrivateKey

	// TODO: find out whether it's a good idea to use rand.Reader (global variables)
	if privKey, err = rsa.GenerateKey(rand.Reader, bits); err != nil {
		return nil, nil, err
	}

	return privKey, &privKey.PublicKey, err
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	var err error
	var pubASN1 []byte

	if pubASN1, err = x509.MarshalPKIXPublicKey(pub); err != nil {
		return nil, err
	}

	//
	var pubBytes []byte

	pubBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(data []byte) (privKey *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(data)
	b := block.Bytes

	if x509.IsEncryptedPEMBlock(block) == true {
		if b, err = x509.DecryptPEMBlock(block, nil); err != nil {
			return privKey, err
		}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		// pkcs1
		if privKey, err = x509.ParsePKCS1PrivateKey(b); err != nil {
			return privKey, err
		}
	case "PRIVATE KEY":
		// pkcs8
		var ifc interface{}
		var ok bool

		if ifc, err = x509.ParsePKCS8PrivateKey(b); err != nil {
			return privKey, err
		}

		if privKey, ok = ifc.(*rsa.PrivateKey); !ok {
			return privKey, fmt.Errorf("Failed to type assertion to *rsa.PrivateKey")
		}
	default:
		return privKey, fmt.Errorf("unsupported %s block.Type", block.Type)
	}

	return privKey, err
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(data []byte) (pubKey *rsa.PublicKey, err error) {
	block, _ := pem.Decode(data)
	b := block.Bytes

	if x509.IsEncryptedPEMBlock(block) == true {
		if b, err = x509.DecryptPEMBlock(block, nil); err != nil {
			return pubKey, err
		}
	}

	//
	var ifc interface{}
	var ok bool

	if ifc, err = x509.ParsePKIXPublicKey(b); err != nil {
		return pubKey, err
	}

	if pubKey, ok = ifc.(*rsa.PublicKey); !ok {
		return pubKey, fmt.Errorf("Failed to type assert to *rsa.PublicKey")
	}

	return pubKey, nil
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	return rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	return rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
}

// HashPassword ...
func HashPassword(plaintextPassword string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(plaintextPassword), bcrypt.DefaultCost)
}

// ValidatePassword ...
func ValidatePassword(hashed string, plaintextPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plaintextPassword))
}

// CreateHash ...
func CreateHash(key string) []byte {
	hash := sha256.Sum256([]byte(key))

	// Alternative way
	//hash := sha256.New()
	//hash.Write([]byte(key))
	//digest := hash.Sum(nil)

	return hash[:]
}

// HMACHash hashes data using a secret key
func HMACHash(message string, secret string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

// EncryptAES ...
func EncryptAES(data []byte, passphrase string) ([]byte, error) {
	// Generate a new aes cipher using our 32 byte long key
	var err error
	var block cipher.Block

	if block, err = aes.NewCipher([]byte(CreateHash(passphrase))); err != nil {
		return nil, err
	}

	//
	var gcm cipher.AEAD

	if gcm, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}

	//
	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptAES ...
func DecryptAES(data []byte, passphrase string) ([]byte, error) {
	var err error
	var block cipher.Block

	key := []byte(CreateHash(passphrase))

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	//
	var gcm cipher.AEAD

	if gcm, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}

	//
	nonceSize := gcm.NonceSize()

	if len(data) < nonceSize {
		return nil, fmt.Errorf("data size is less than nonceSize")
	}

	//
	var plaintext []byte

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	if plaintext, err = gcm.Open(nil, nonce, ciphertext, nil); err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Package util ...
//
// PKCS#1 and PKCS#8 format for RSA private key
//
// PKCS1, available in several versions as rfcs 2313 2437 3447 and 8017, is primarily about using the RSA algorithm for cryptography including encrypting decrypting signing and verifying. But since crypto is often used between systems or at least programs it is convenient to have a defined, interoperable format for keys, and PKCS1 defines fairly minimal formats for RSA public and private keys in appendix A.1. As Luke implied this uses ASN.1 conventionally encoded as DER, which is a standard for interoperably encoding data of almost any kind.
//
// PKCS8 available as rfc5208 on the other hand is a standard for handling private keys for all algorithms, not just RSA. It also uses ASN.1 DER, and starts by simply combining an AlgorithmIdentifier, an ASN.1 structure (first) defined by X.509 which not very surprisingly identifies an algorithm, with an OCTET STRING which contains a representation of the key in a fashion depending on the algorithm. For algorithm RSA, identified by an AlgorithmIdentifier containing an OID which means rsaEncryption, the OCTET STRING contains the PKCS1 private key encoding. PKCS8 also allows arbitrary 'attributes' to be added, but this is rarely used. (E.g. Unable to convert .jks to .pkcs12: excess private key)
//
// PKCS8 also provides an option to encrypt the private key, using password-based encryption (in practice though not explicitly required). This is common, especially when PKCS8 is used as the privatekey portion of PKCS12/PFX, though not universal.
//
// Since most systems today need to support multiple algorithms, and wish to be able to adapt to new algorithms as they are developed, PKCS8 is preferred for privatekeys, and a similar any-algorithm scheme defined by X.509 for publickeys. Although PKCS12/PFX is often preferred to both.
//
// Neither of these has anything to do with certificates or other PKI objects like CSRs, CRLs, OCSP, SCTs, etc. Those are defined by other standards, including some other members of the PKCS series -- although they may use the keys defined by these standards.
//
// PEM format as Luke said is a way of formatting, or (super)encoding, (almost any) binary/DER data in a way that is more convenient. It derives from a 1990s attempt at secure email named Privacy-Enhanced Mail hence PEM. In those days email systems often could transmit, or at least reliably transmit, only printable text with a limited character set, and often only limited line length, so PEM encoded binary data as base64 with line length 64. The PEM scheme itself was not very successful and has been superseded by others like PGP and S/MIME, but the format it defined is still used. Nowadays email systems often can transmit binary data, but as Luke said copy-and-paste often can only handle displayed characters so PEM is still useful, and in addition easier for humans to recognize.
//
// To be more exact, PEM encodes some data, such as but not limited to a PKCS1 or PKCS8 key or a certificate, CSR, etc, as:
//
// - a line consisting of 5 hyphens, the word BEGIN, one or a few (space-separated) words defining the type of data, and 5 hyphens
// - an optional (and rare) rfc822-style header, terminated by an empty line
// - base64 of the data, broken into lines of 64 characters (except the last); some programs instead use the (slightly newer) MIME limit of 76 characters
// - a line like the BEGIN line but with END instead
//
// Some readers check/enforce the line length and END line and some don't, so if you get those wrong you may create files that sometimes work and sometimes don't, which is annoying to debug.
//
// Reference:
// https://gist.github.com/miguelmota/3ea9286bd1d3c2a985b67cac4ba2130a
// https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key
// https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
// https://tutorialedge.net/golang/go-encrypt-decrypt-aes-tutorial/
// https://github.com/gtank/cryptopasta
package util

import (
	"crypto"
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
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	var err error
	var pubASN1 []byte

	if pubASN1, err = x509.MarshalPKIXPublicKey(pub); err != nil {
		return nil, err
	}

	//
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	var err error
	block, _ := pem.Decode(data)
	b := block.Bytes

	if x509.IsEncryptedPEMBlock(block) {
		if b, err = x509.DecryptPEMBlock(block, nil); err != nil {
			return nil, err
		}
	}

	//
	var privKey *rsa.PrivateKey

	switch block.Type {
	case "RSA PRIVATE KEY":
		// pkcs1
		if privKey, err = x509.ParsePKCS1PrivateKey(b); err != nil {
			return nil, err
		}
	case "PRIVATE KEY":
		// pkcs8
		var ifc interface{}
		var ok bool

		if ifc, err = x509.ParsePKCS8PrivateKey(b); err != nil {
			return nil, err
		}

		if privKey, ok = ifc.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("failed to type assertion to *rsa.PrivateKey")
		}
	default:
		return nil, fmt.Errorf("unsupported %s block.Type", block.Type)
	}

	return privKey, nil
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(data []byte) (*rsa.PublicKey, error) {
	var err error
	block, _ := pem.Decode(data)
	b := block.Bytes

	if x509.IsEncryptedPEMBlock(block) {
		if b, err = x509.DecryptPEMBlock(block, nil); err != nil {
			return nil, err
		}
	}

	//
	var ifc interface{}

	if ifc, err = x509.ParsePKIXPublicKey(b); err != nil {
		return nil, err
	}

	//
	var pubKey *rsa.PublicKey
	var ok bool

	if pubKey, ok = ifc.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("failed to type assert to *rsa.PublicKey")
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
func CreateHash(data string) []byte {
	digest := sha256.Sum256([]byte(data))

	// Alternative way
	//hash := sha256.New()
	//hash.Write([]byte(data))
	//digest := hash.Sum(nil)

	return digest[:]
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

	if block, err = aes.NewCipher(CreateHash(passphrase)); err != nil {
		return nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	var gcm cipher.AEAD

	if gcm, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())

	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

// DecryptAES ...
func DecryptAES(data []byte, passphrase string) ([]byte, error) {
	var err error
	var block cipher.Block

	key := CreateHash(passphrase)

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

	// TODO: do we really need this checking?
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

// SignSignature signs the data with a private key
func SignSignature(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
}

// VerifySignature verifies the data with a public key
func VerifySignature(publicKey *rsa.PublicKey, data []byte, sig []byte) error {
	digest := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], sig)
}

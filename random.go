package util

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())

	//Reader = &devReader{name: "/dev/urandom"}
}

// RandomNumber generates a random number in a given range.
// This code is vulnerable to a time attack. Given knowledge of the seed, the output is deterministic.
// If you are on linux, you could poll "/dev/random" or "/dev/urandom" and have that be your seed. Or better yet, use crypto/rand.
// Reference:
// http://golangcookbook.blogspot.ca/2012/11/generate-random-number-in-given-range.html
func RandomNumber(min, max int) int {
	return rand.Intn(max-min) + min
}

// RandomNumInSlice ...
func RandomNumInSlice(slice []int) int {
	return slice[rand.Intn(len(slice))]
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
// Reference:
// https://elithrar.github.io/article/generating-secure-random-numbers-crypto-rand/
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := cryptorand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

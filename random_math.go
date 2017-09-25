package util

import (
	"math/rand"
	"time"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
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

// RandStringBytes ...
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// RandStringRunes ...
func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

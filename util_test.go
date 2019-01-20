//
// go test -v -run="RandomNumber|GenerateRandomString" util_test.go
//
package util_test

import (
	"fmt"
	"math"
	"strconv"
	"testing"
)

import (
	"github.com/junxie6/util"
)

func TestExecCommand(t *testing.T) {
	var out string
	var err error
	var exitStatus int
	cmdArgs := []string{"sh", "-c", `ls /bin/bash`}

	if out, err, exitStatus = util.ExecCommand(cmdArgs, 3); err != nil {
		fmt.Printf("Error (%d): %s\n", exitStatus, err.Error())
		return
	}

	fmt.Printf("Out (%d): %s\n", exitStatus, out)
}

func TestNumOfDigits(t *testing.T) {
	num := 0
	numAdjusted := 0
	iLen := 0
	NumOfDigit := 0

	powOfTenArr := util.PowOfTenArr()

	for _, num = range powOfTenArr {
		for i := -10000; i < 100000; i++ {
			numAdjusted = num + i
			iLen = len(strconv.Itoa(int(util.AbsWithTwosComplement(int64(numAdjusted)))))
			NumOfDigit = util.NumOfDigits(numAdjusted)

			if NumOfDigit != iLen {
				t.Errorf("%d; got %v; want %v\n", numAdjusted, NumOfDigit, iLen)
			}
		}
	}

	//
	//for num = 0; num < math.MaxInt64; num++ {
	//	iLen = len(strconv.Itoa(num))
	//	NumOfDigit = util.NumOfDigits(num)

	//	if NumOfDigit != iLen {
	//		t.Errorf("got %v; want %v\n", NumOfDigit, iLen)
	//	}
	//}

	//
	iLen = len(strconv.Itoa(math.MaxInt64))
	NumOfDigit = util.NumOfDigits(math.MaxInt64)

	if NumOfDigit != iLen {
		t.Errorf("got %v; want %v\n", NumOfDigit, iLen)
	}
}

func BenchmarkAbsWithTwosComplement(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.AbsWithTwosComplement(math.MaxInt64)
	}
}

func BenchmarkAbsWithBranch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.AbsWithBranch(math.MaxInt64)
	}
}

func BenchmarkNumOfDigits(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.NumOfDigits(math.MaxInt64)
	}
}

func BenchmarkNumOfDigitsString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.NumOfDigitsString(math.MaxInt64)
	}
}

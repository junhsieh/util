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
	numOfDigitsString := 0
	numOfDigitsDivideAndConquer := 0
	numOfDigitsRepeatedDivide := 0
	numOfDigitsDivideAndConquerHardCoded := 0

	powOfTenArr := util.PowOfTenArr()

	for _, num = range powOfTenArr {
		for i := -10000; i < 100000; i++ {
			numAdjusted = num + i
			numOfDigitsString = len(strconv.Itoa(int(util.AbsWithTwosComplement(int64(numAdjusted)))))
			numOfDigitsDivideAndConquer = util.NumOfDigitsDivideAndConquer(numAdjusted)
			numOfDigitsRepeatedDivide = util.NumOfDigitsRepeatedDivide(numAdjusted)
			numOfDigitsDivideAndConquerHardCoded = util.NumOfDigitsDivideAndConquerHardCoded(numAdjusted)

			if numOfDigitsDivideAndConquer != numOfDigitsString {
				t.Errorf("%d; got %v; want %v\n", numAdjusted, numOfDigitsDivideAndConquer, numOfDigitsString)
			}

			if numOfDigitsRepeatedDivide != numOfDigitsString {
				t.Errorf("%d; got %v; want %v\n", numAdjusted, numOfDigitsRepeatedDivide, numOfDigitsString)
			}

			if numOfDigitsDivideAndConquerHardCoded != numOfDigitsString {
				t.Errorf("%d; got %v; want %v\n", numAdjusted, numOfDigitsDivideAndConquerHardCoded, numOfDigitsString)
			}
		}
	}

	//
	//for num = 0; num < math.MaxInt64; num++ {
	//	numOfDigitsString = util.NumOfDigitsString(num)
	//	numOfDigitsDivideAndConquer = util.NumOfDigitsDivideAndConquer(num)

	//	if numOfDigitsDivideAndConquer != numOfDigitsString {
	//		t.Errorf("got %v; want %v\n", numOfDigits, numOfDigitsString)
	//	}
	//}

	//
	numAdjusted = math.MaxInt64

	numOfDigitsString = util.NumOfDigitsString(numAdjusted)
	numOfDigitsDivideAndConquer = util.NumOfDigitsDivideAndConquer(numAdjusted)
	numOfDigitsRepeatedDivide = util.NumOfDigitsRepeatedDivide(numAdjusted)
	numOfDigitsDivideAndConquerHardCoded = util.NumOfDigitsDivideAndConquerHardCoded(numAdjusted)

	if numOfDigitsDivideAndConquer != numOfDigitsString {
		t.Errorf("%d; got %v; want %v\n", numAdjusted, numOfDigitsDivideAndConquer, numOfDigitsString)
	}

	if numOfDigitsRepeatedDivide != numOfDigitsString {
		t.Errorf("%d; got %v; want %v\n", numAdjusted, numOfDigitsRepeatedDivide, numOfDigitsString)
	}

	if numOfDigitsDivideAndConquerHardCoded != numOfDigitsString {
		t.Errorf("%d; got %v; want %v\n", numAdjusted, numOfDigitsDivideAndConquerHardCoded, numOfDigitsString)
	}
}

func TestNotYet(t *testing.T) {
	digitArr := util.IntToDigitArr(123456)
	fmt.Printf("HERE: %v_%d_%d\n", digitArr, len(digitArr), cap(digitArr))
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

func BenchmarkNumOfDigitsDivideAndConquer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.NumOfDigitsDivideAndConquer(math.MaxInt64)
	}
}

func BenchmarkNumOfDigitsString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.NumOfDigitsString(math.MaxInt64)
	}
}

func BenchmarkNumOfDigitsRepeatedDivide(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.NumOfDigitsRepeatedDivide(math.MaxInt64)
	}
}

func BenchmarkNumOfDigitsDivideAndConquerHardCoded(b *testing.B) {
	for i := 0; i < b.N; i++ {
		util.NumOfDigitsDivideAndConquerHardCoded(math.MaxInt64)
	}
}

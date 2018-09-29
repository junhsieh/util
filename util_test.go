//
// go test -v -run="RandomNumber|GenerateRandomString" util_test.go
//
package util_test

import (
	"fmt"
	"testing"
)

import (
	"github.com/junxie6/util"
)

func TestRandomNumber(t *testing.T) {
	for i := 0; i < 10; i++ {
		num := util.RandomNumber(0, 2)
		fmt.Printf("%d\n", num)
	}
}

func TestGenerateRandomString(t *testing.T) {
	var err error
	var str string

	for i := 0; i < 10; i++ {
		str, err = util.GenerateRandomString(10)

		if err != nil {
			t.Errorf("%s", err.Error())
			return
		}

		fmt.Printf("%s\n", str)
	}

	fff := util.RandStringBytes(20)
	fmt.Printf("HERE %s\n", fff)
}

func TestGenerateRandomDate(t *testing.T) {
	d := util.RandomDate(3)
	fmt.Printf("Date: %s\n", d)
}

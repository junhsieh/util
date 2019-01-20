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

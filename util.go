package util

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func ReadInput() (string, error) {
	return bufio.NewReader(os.Stdin).ReadString('\n')
}

func WriteFile(fileName string, data []byte) error {
	return ioutil.WriteFile(fileName, data, 0644)
}

func ReadFile(fileName string) ([]byte, error) {
	return ioutil.ReadFile(fileName)
}

func ReadWebContent(url string) ([]byte, error) {
	resp, err := http.Get(url)

	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("StatusCode: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return body, nil
}

func DaysAgo(t time.Time) int {
	return int(time.Since(t).Hours() / 24)
}

func Now() string {
	// Mon Jan 2 15:04:05 -0700 MST 2006
	return time.Now().Format("2006-01-02 15:04:05")
}

func ConvStrToTime(str string) (time.Time, error) {
	layout := "2006-01-02" // Mon Jan 2 15:04:05 -0700 MST 2006
	return time.Parse(layout, str)
}

// WaitForServer attempts to contact the server of a URL.
// It tries for one minute using exponential backoff.
// It reports an error if all attempts fail.
func WaitForServer(url string) error {
	const timeout = 1 * time.Minute
	deadline := time.Now().Add(timeout)
	for tries := 0; time.Now().Before(deadline); tries++ {
		_, err := http.Head(url)
		if err == nil {
			return nil // success
		}
		log.Printf("server not responding (%s); retrying...", err)
		time.Sleep(time.Second << uint(tries)) // exponential backoff
	}
	return fmt.Errorf("server %s failed to respond after %s", url, timeout)
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
	return hash[:]
}

// EncryptAES ...
// Reference: https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
func EncryptAES(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(CreateHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// DecryptAES ...
func DecryptAES(data []byte, passphrase string) []byte {
	key := []byte(CreateHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

// StrutToSliceOfFieldAddress can be used for rows.Scan() for setting the value for database fields from SQL query.
func StrutToSliceOfFieldAddress(theStruct interface{}) []interface{} {
	fieldArr := reflect.ValueOf(theStruct).Elem()
	fieldPtrArr := make([]interface{}, 0)

	for i := 0; i < fieldArr.NumField(); i++ {
		typeField := fieldArr.Type().Field(i)

		if typeField.Tag.Get("fieldName") == "-" {
			continue
		}

		valueField := fieldArr.Field(i)

		fieldPtrArr = append(fieldPtrArr, valueField.Addr().Interface())
	}

	return fieldPtrArr
}

// Fill a slice with values.
func SliceFill(num int, str string) []string {
	slice := make([]string, num)

	for k, _ := range slice {
		slice[k] = str
	}

	return slice
}

// Generate the placeholders for SQL query.
func Placeholder(num int) string {
	return strings.Join(SliceFill(num, "?"), ",")
}

// PrintStructJSON ...
func PrintStructJSON(s interface{}) {
	if strJSON, err := json.MarshalIndent(s, "", " "); err != nil {
		log.Printf("JSON marshaling failed: %s\n", err)
	} else {
		fmt.Printf("%s\n", strJSON)
	}
}

// PrintJSON ...
func PrintJSON(rowArr []interface{}) {
	// produces neatly indented output
	if data, err := json.MarshalIndent(rowArr, "", " "); err != nil {
		log.Printf("JSON marshaling failed: %s\n", err)
	} else {
		fmt.Printf("%s\n", data)
	}
}

// PrintErrJSON ...
func PrintErrJSON(rowArr []error) {
	b := make([]interface{}, len(rowArr))
	for i := range rowArr {
		b[i] = rowArr[i].Error()
	}
	PrintJSON(b)
}

// ConvErrArrToJSON ...
func ConvErrArrToJSON(errArr []error) string {
	strArr := ConvErrArrToStringArr(errArr)

	outMap := map[string]interface{}{
		"Status": false,
		"ErrArr": strArr,
	}

	var byteJSON []byte
	var err error

	if byteJSON, err = json.Marshal(outMap); err != nil {
		return `{"Status":false,"ErrArr":["` + err.Error() + `"]}`
	}

	return string(byteJSON)
}

// ConvSliceToInterface ...
func ConvSliceToInterface(slice interface{}) []interface{} {
	s := reflect.ValueOf(slice)

	if s.Kind() != reflect.Slice {
		log.Printf("ConvSliceToInterface() given a non-slice type")
		return nil
	}

	ret := make([]interface{}, s.Len())

	for i := 0; i < s.Len(); i++ {
		ret[i] = s.Index(i).Interface()
	}

	return ret
}

// ConvErrArrToStringArr ...
func ConvErrArrToStringArr(errArr []error) []string {
	strArr := make([]string, len(errArr))
	for i := range errArr {
		strArr[i] = errArr[i].Error()
	}
	return strArr
}

// DecodeJSONStreamStruct ...
func DecodeJSONStreamStruct(r *http.Request, v interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return err
	}

	return nil
}

// DecodeJSONStreamMap ...
func DecodeJSONStreamMap(r *http.Request) (map[string]interface{}, error) {
	var data interface{}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, err
	}

	return data.(map[string]interface{}), nil
}

// FormValueArr ...
func FormValueArr(r *http.Request) map[string]string {
	mapArr := map[string]string{}

	if r.Form == nil {
		r.ParseMultipartForm(32 << 20) // 32 MB
	}

	for k, vs := range r.Form {
		if len(vs) > 0 {
			mapArr[k] = vs[0]
		} else {
			mapArr[k] = ""
		}
	}

	return mapArr
}

// Atoi ...
func Atoi(num string) int {
	i, _ := strconv.ParseInt(num, 10, 0)
	return int(i)
}

// Atoi64 ...
func Atoi64(num string) int64 {
	i, _ := strconv.ParseInt(num, 10, 64)
	return i
}

// StructFieldNameArr ...
func StructFieldNameArr(s interface{}) []string {
	sFields := reflect.TypeOf(s)
	fieldNameArr := make([]string, sFields.NumField())

	for i := 0; i < sFields.NumField(); i++ {
		fieldNameArr[i] = sFields.Field(i).Name
	}

	return fieldNameArr
}

// InArrayV1 ...
func InArrayV1(val interface{}, array interface{}) (exists bool, index int) {
	exists = false
	index = -1

	switch reflect.TypeOf(array).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(array)

		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
				index = i
				exists = true
				return
			}
		}
	}

	return
}

// InArrayV2 ...
func InArrayV2(v interface{}, in interface{}) (ok bool, i int) {
	val := reflect.Indirect(reflect.ValueOf(in))
	switch val.Kind() {
	case reflect.Slice, reflect.Array:
		for ; i < val.Len(); i++ {
			if ok = v == val.Index(i).Interface(); ok {
				return
			}
		}
	}
	return
}

// InArrayInt ...
func InArrayInt(v int, vArr []int) bool {
	for _, vv := range vArr {
		if v == vv {
			return true
		}
	}

	return false
}

// InArrayStr ...
func InArrayStr(v string, vArr []string) bool {
	for _, vv := range vArr {
		if v == vv {
			return true
		}
	}

	return false
}

// FGColor ...
var FGColor = struct {
	White, Red, Green, Yellow string
}{
	White:  "1;37",
	Red:    "0;31",
	Green:  "0;32",
	Yellow: "1;33",
}

// EchoColor ...
func EchoColor(msg string, color string) string {
	return "\033[" + color + "m" + msg + "\033[0m"
}

// Close is used for defer statement. Example: defer Close(VarResource)
func Close(c io.Closer) {
	// Note: do we need to add recover() here?
	if err := c.Close(); err != nil {
		log.Printf(err.Error())
	}
}

// DeferClose ...
// defer DeferClose(&err, rsp.Body.Close)
// Note: https://github.com/carlmjohnson/json-tidy/blob/master/json-tidy.go#L91:L96
func DeferClose(e *error, c io.Closer) {
	var err error

	if err = c.Close(); err != nil {
		if *e == nil {
			*e = err
		}
	}
}

// JSONDeepEqual ...
func JSONDeepEqual(s1 string, s2 string) (bool, error) {
	var m1, m2 map[string]interface{}

	if err := json.Unmarshal([]byte(s1), &m1); err != nil {
		return false, err
	}

	if err := json.Unmarshal([]byte(s2), &m2); err != nil {
		return false, err
	}

	return reflect.DeepEqual(m1, m2), nil
}

// StrToUint32 converts uint32 string to uint32 integer
func StrToUint32(num string) uint32 {
	var n uint64
	var err error

	if n, err = strconv.ParseUint(num, 10, 32); err != nil {
		return 0
	}

	return uint32(n)
}

// Uint32ToStr converts uint32 integer to string
func Uint32ToStr(num uint32) string {
	return strconv.FormatUint(uint64(num), 10)
}

// ExecCommand ...
func ExecCommand(cmdArgs []string, timeout int) (string, error, int) {
	var cmd *exec.Cmd
	var bufOut bytes.Buffer
	var bufErr bytes.Buffer
	var err error

	cmd = exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdout = &bufOut
	cmd.Stderr = &bufErr

	if err = cmd.Start(); err != nil {
		return "", err, -1
	}

	// Use a channel to signal completion
	done := make(chan error)

	go func() {
		done <- cmd.Wait()
	}()

	//
	select {
	case <-time.After(time.Duration(timeout) * time.Second):
		// Timeout, try to kill the process gracefully first
		// NOTE: You can use signal.Notify to catch the signals and run a cleanup code before shutting down.
		// Reference:
		// https://stackoverflow.com/questions/11268943/is-it-possible-to-capture-a-ctrlc-signal-and-run-a-cleanup-function-in-a-defe
		// https://stackoverflow.com/questions/18106749/golang-catch-signals
		// https://gobyexample.com/signals
		if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
			return "", err, -1
		}

		// Kill the process forcefully.
		select {
		case <-time.After(3 * time.Second):
			if err = cmd.Process.Kill(); err != nil {
				return "", err, -1
			}
		case err = <-done:
			return handleExecCommand(cmd, err)
		}
	case err = <-done:
		return handleExecCommand(cmd, err)
	}

	return "", errors.New("Unexpected (select did not handle return properly"), -1
}

func handleExecCommand(cmd *exec.Cmd, err error) (string, error, int) {
	if err != nil {
		var ok bool
		var exitErr *exec.ExitError
		var exitStatus syscall.WaitStatus

		// Check to see if err is *exec.ExitError or something (most likely system generated error) else
		if exitErr, ok = err.(*exec.ExitError); !ok {
			return cmd.Stdout.(*bytes.Buffer).String(), err, -1
		}

		if exitStatus, ok = exitErr.Sys().(syscall.WaitStatus); !ok {
			return cmd.Stdout.(*bytes.Buffer).String(), errors.New("exitStatus could not be type assertion to syscall.WaitStatus"), -1
		}

		return cmd.Stdout.(*bytes.Buffer).String(), errors.New(cmd.Stderr.(*bytes.Buffer).String()), exitStatus.ExitStatus()
	}

	return cmd.Stdout.(*bytes.Buffer).String(), nil, 0
}

// IntEqual ...
func IntEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// AbsWithTwosComplement returns the absolute value of x.
// NOTE: -9223372036854775808 could not be convert.
// Reference:
// http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
func AbsWithTwosComplement(n int64) int64 {
	y := n >> 63
	return (n ^ y) - y
}

// AbsWithBranch returns the absolute value of x.
// NOTE: -9223372036854775808 could not be convert.
func AbsWithBranch(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// Pow computes a**b using binary powering algorithm
// See Donald Knuth, The Art of Computer Programming, Volume 2, Section 4.6.3
func Pow(a int, b int) int {
	result := 1
	for b > 0 {
		if b&1 != 0 {
			result *= a
		}
		b >>= 1
		a *= a
	}
	return result
}

// PowOfTenArr ...
func PowOfTenArr() []int {
	return []int{
		1,                   // 0
		10,                  // 1
		100,                 // 2
		1000,                // 3
		10000,               // 4
		100000,              // 5
		1000000,             // 6
		10000000,            // 7
		100000000,           // 8
		1000000000,          // 9
		10000000000,         // 10
		100000000000,        // 11
		1000000000000,       // 12
		10000000000000,      // 13
		100000000000000,     // 14
		1000000000000000,    // 15
		10000000000000000,   // 16
		100000000000000000,  // 17
		1000000000000000000, // 18
	}
}

// NumOfDigits (Divide and conquer approach) ...
// Here are some ways of determining the number of digits in an integer:
// - string method
// - log10 method
// - repeated divide method
// - divide-and-conquer method
// Reference:
// https://stackoverflow.com/questions/1306727/way-to-get-number-of-digits-in-an-int/1308407#1308407
func NumOfDigitsDivideAndConquer(num int) int {
	powOfTenArr := PowOfTenArr()
	powOfTenLen := len(powOfTenArr)

	return numOfDigitsDivideAndConquer(powOfTenArr, 0, powOfTenLen, int(AbsWithTwosComplement(int64(num))))
}

func numOfDigitsDivideAndConquer(powOfTenArr []int, startPos, endPos, num int) int {
	middlePos := (endPos-startPos)/2 + startPos

	if num < powOfTenArr[middlePos] {
		if (middlePos - startPos) == 1 {
			//fmt.Printf("END: %d\t%d\t%d\n", startPos, middlePos, endPos)
			return middlePos
		}

		//fmt.Printf("SML: %d\t%d\t%d\n", startPos, middlePos, endPos)
		return numOfDigitsDivideAndConquer(powOfTenArr, startPos, middlePos, num)
	} else {
		if (endPos - middlePos) == 1 {
			//fmt.Printf("END: %d\t%d\t%d\n", startPos, middlePos, endPos)
			return middlePos + 1
		}

		//fmt.Printf("BIG: %d\t%d\t%d\n", startPos, middlePos, endPos)
		return numOfDigitsDivideAndConquer(powOfTenArr, middlePos, endPos, num)
	}
}

// NumOfDigitsDivideAndConquerHardCoded (Divide and conquer hard-coded approach) ...
func NumOfDigitsDivideAndConquerHardCoded(num int) int {
	num = int(AbsWithTwosComplement(int64(num)))

	// 9
	if num < 1000000000 {
		// 4
		if num < 10000 {
			// 2
			if num < 100 {
				// 1
				if num < 10 {
					return 1
				} else {
					return 2
				}
			} else {
				// 3
				if num < 1000 {
					return 3
				} else {
					return 4
				}
			}
		} else {
			// 6
			if num < 1000000 {
				// 5
				if num < 100000 {
					return 5
				} else {
					return 6
				}
			} else {
				// 7
				if num < 10000000 {
					return 7
				} else {
					// 8
					if num < 100000000 {
						return 8
					} else {
						return 9
					}
				}
			}
		}
	} else {
		// 14
		if num < 100000000000000 {
			// 11
			if num < 100000000000 {
				// 10
				if num < 10000000000 {
					return 10
				} else {
					return 11
				}
			} else {
				// 12
				if num < 1000000000000 {
					return 12
				} else {
					// 13
					if num < 10000000000000 {
						return 13
					} else {
						return 14
					}
				}
			}
		} else {
			// 16
			if num < 10000000000000000 {
				// 15
				if num < 1000000000000000 {
					return 15
				} else {
					return 16
				}
			} else {
				// 17
				if num < 100000000000000000 {
					return 17
				} else {
					// 18
					if num < 1000000000000000000 {
						return 18
					} else {
						return 19
					}
				}
			}
		}
	}
}

// NumOfDigitsString (string approach) ...
func NumOfDigitsString(num int) int {
	num = int(AbsWithTwosComplement(int64(num)))
	return len(strconv.Itoa(num))
}

// NumOfDigitsLog10 (log10 approach) ...
// NOTE: this function is not 100% correct
func NumOfDigitsLog10(num int) int {
	if num == 0 {
		return 1
	}

	num = int(AbsWithTwosComplement(int64(num)))
	return int(math.Log10(float64(num))) + 1
}

// NumOfDigitsRepeatedDivide (repeated divide approach) ...
func NumOfDigitsRepeatedDivide(num int) int {
	if num == 0 {
		return 1
	}

	num = int(AbsWithTwosComplement(int64(num)))
	l := 0

	for ; num > 0; l++ {
		num /= 10
	}
	return l
}

// IntToDigitArr separates the digits of an integer into a slice
// Reference:
// https://stackoverflow.com/questions/1613317/fastest-way-to-separate-the-digits-of-an-int-into-an-array-in-net
// https://stackoverflow.com/questions/4261589/how-do-i-split-an-int-into-its-digits
func IntToDigitArr(num int) []int {
	size := NumOfDigitsDivideAndConquerHardCoded(num)
	digitArr := make([]int, size)

	for i := size - 1; i >= 0; i-- {
		digitArr[i] = num % 10
		num /= 10
	}

	return digitArr
}

// HMACHash hashes data using a secret key
func HMACHash(message string, secret string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

// CopyIntSlice ...
func CopyIntSlice(dst []int, src []int) int {
	if src == nil {
		dst = nil
		return 0
	}
	dst = make([]int, len(src))
	return copy(dst, src)
}

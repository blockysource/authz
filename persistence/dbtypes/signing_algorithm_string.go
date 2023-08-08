// Code generated by "enumer -type=SigningAlgorithm -text -sql -trimprefix=SigningAlgorithm -output=signing_algorithm_string.go"; DO NOT EDIT.

package dbtypes

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

const _SigningAlgorithmName = "NoneHS256HS384HS512RS256RS384RS512ES256ES384ES512PS256PS384PS512EdDSA"

var _SigningAlgorithmIndex = [...]uint8{0, 4, 9, 14, 19, 24, 29, 34, 39, 44, 49, 54, 59, 64, 69}

const _SigningAlgorithmLowerName = "nonehs256hs384hs512rs256rs384rs512es256es384es512ps256ps384ps512eddsa"

func (i SigningAlgorithm) String() string {
	i -= 1
	if i < 0 || i >= SigningAlgorithm(len(_SigningAlgorithmIndex)-1) {
		return fmt.Sprintf("SigningAlgorithm(%d)", i+1)
	}
	return _SigningAlgorithmName[_SigningAlgorithmIndex[i]:_SigningAlgorithmIndex[i+1]]
}

// An "invalid array index" compiler error signifies that the constant values have changed.
// Re-run the stringer command to generate them again.
func _SigningAlgorithmNoOp() {
	var x [1]struct{}
	_ = x[SigningAlgorithmNone-(1)]
	_ = x[SigningAlgorithmHS256-(2)]
	_ = x[SigningAlgorithmHS384-(3)]
	_ = x[SigningAlgorithmHS512-(4)]
	_ = x[SigningAlgorithmRS256-(5)]
	_ = x[SigningAlgorithmRS384-(6)]
	_ = x[SigningAlgorithmRS512-(7)]
	_ = x[SigningAlgorithmES256-(8)]
	_ = x[SigningAlgorithmES384-(9)]
	_ = x[SigningAlgorithmES512-(10)]
	_ = x[SigningAlgorithmPS256-(11)]
	_ = x[SigningAlgorithmPS384-(12)]
	_ = x[SigningAlgorithmPS512-(13)]
	_ = x[SigningAlgorithmEdDSA-(14)]
}

var _SigningAlgorithmValues = []SigningAlgorithm{SigningAlgorithmNone, SigningAlgorithmHS256, SigningAlgorithmHS384, SigningAlgorithmHS512, SigningAlgorithmRS256, SigningAlgorithmRS384, SigningAlgorithmRS512, SigningAlgorithmES256, SigningAlgorithmES384, SigningAlgorithmES512, SigningAlgorithmPS256, SigningAlgorithmPS384, SigningAlgorithmPS512, SigningAlgorithmEdDSA}

var _SigningAlgorithmNameToValueMap = map[string]SigningAlgorithm{
	_SigningAlgorithmName[0:4]:        SigningAlgorithmNone,
	_SigningAlgorithmLowerName[0:4]:   SigningAlgorithmNone,
	_SigningAlgorithmName[4:9]:        SigningAlgorithmHS256,
	_SigningAlgorithmLowerName[4:9]:   SigningAlgorithmHS256,
	_SigningAlgorithmName[9:14]:       SigningAlgorithmHS384,
	_SigningAlgorithmLowerName[9:14]:  SigningAlgorithmHS384,
	_SigningAlgorithmName[14:19]:      SigningAlgorithmHS512,
	_SigningAlgorithmLowerName[14:19]: SigningAlgorithmHS512,
	_SigningAlgorithmName[19:24]:      SigningAlgorithmRS256,
	_SigningAlgorithmLowerName[19:24]: SigningAlgorithmRS256,
	_SigningAlgorithmName[24:29]:      SigningAlgorithmRS384,
	_SigningAlgorithmLowerName[24:29]: SigningAlgorithmRS384,
	_SigningAlgorithmName[29:34]:      SigningAlgorithmRS512,
	_SigningAlgorithmLowerName[29:34]: SigningAlgorithmRS512,
	_SigningAlgorithmName[34:39]:      SigningAlgorithmES256,
	_SigningAlgorithmLowerName[34:39]: SigningAlgorithmES256,
	_SigningAlgorithmName[39:44]:      SigningAlgorithmES384,
	_SigningAlgorithmLowerName[39:44]: SigningAlgorithmES384,
	_SigningAlgorithmName[44:49]:      SigningAlgorithmES512,
	_SigningAlgorithmLowerName[44:49]: SigningAlgorithmES512,
	_SigningAlgorithmName[49:54]:      SigningAlgorithmPS256,
	_SigningAlgorithmLowerName[49:54]: SigningAlgorithmPS256,
	_SigningAlgorithmName[54:59]:      SigningAlgorithmPS384,
	_SigningAlgorithmLowerName[54:59]: SigningAlgorithmPS384,
	_SigningAlgorithmName[59:64]:      SigningAlgorithmPS512,
	_SigningAlgorithmLowerName[59:64]: SigningAlgorithmPS512,
	_SigningAlgorithmName[64:69]:      SigningAlgorithmEdDSA,
	_SigningAlgorithmLowerName[64:69]: SigningAlgorithmEdDSA,
}

var _SigningAlgorithmNames = []string{
	_SigningAlgorithmName[0:4],
	_SigningAlgorithmName[4:9],
	_SigningAlgorithmName[9:14],
	_SigningAlgorithmName[14:19],
	_SigningAlgorithmName[19:24],
	_SigningAlgorithmName[24:29],
	_SigningAlgorithmName[29:34],
	_SigningAlgorithmName[34:39],
	_SigningAlgorithmName[39:44],
	_SigningAlgorithmName[44:49],
	_SigningAlgorithmName[49:54],
	_SigningAlgorithmName[54:59],
	_SigningAlgorithmName[59:64],
	_SigningAlgorithmName[64:69],
}

// SigningAlgorithmString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func SigningAlgorithmString(s string) (SigningAlgorithm, error) {
	if val, ok := _SigningAlgorithmNameToValueMap[s]; ok {
		return val, nil
	}

	if val, ok := _SigningAlgorithmNameToValueMap[strings.ToLower(s)]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to SigningAlgorithm values", s)
}

// SigningAlgorithmValues returns all values of the enum
func SigningAlgorithmValues() []SigningAlgorithm {
	return _SigningAlgorithmValues
}

// SigningAlgorithmStrings returns a slice of all String values of the enum
func SigningAlgorithmStrings() []string {
	strs := make([]string, len(_SigningAlgorithmNames))
	copy(strs, _SigningAlgorithmNames)
	return strs
}

// IsASigningAlgorithm returns "true" if the value is listed in the enum definition. "false" otherwise
func (i SigningAlgorithm) IsASigningAlgorithm() bool {
	for _, v := range _SigningAlgorithmValues {
		if i == v {
			return true
		}
	}
	return false
}

// MarshalText implements the encoding.TextMarshaler interface for SigningAlgorithm
func (i SigningAlgorithm) MarshalText() ([]byte, error) {
	return []byte(i.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface for SigningAlgorithm
func (i *SigningAlgorithm) UnmarshalText(text []byte) error {
	var err error
	*i, err = SigningAlgorithmString(string(text))
	return err
}

func (i SigningAlgorithm) Value() (driver.Value, error) {
	return i.String(), nil
}

func (i *SigningAlgorithm) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	var str string
	switch v := value.(type) {
	case []byte:
		str = string(v)
	case string:
		str = v
	case fmt.Stringer:
		str = v.String()
	default:
		return fmt.Errorf("invalid value of SigningAlgorithm: %[1]T(%[1]v)", value)
	}

	val, err := SigningAlgorithmString(str)
	if err != nil {
		return err
	}

	*i = val
	return nil
}

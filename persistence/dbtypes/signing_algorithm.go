package dbtypes

//go:generate go run github.com/dmarkham/enumer -type=SigningAlgorithm -text -sql -trimprefix=SigningAlgorithm -output=signing_algorithm_string.go

// SigningAlgorithm is the wrapper over the Signing algorithm that implements
// the sql.Scanner and driver.Valuer interfaces.
// It can be used as an enum, or with the String() method to get the string.
type SigningAlgorithm int

const (
	_ SigningAlgorithm = iota
	SigningAlgorithmNone
	SigningAlgorithmHS256
	SigningAlgorithmHS384
	SigningAlgorithmHS512
	SigningAlgorithmRS256
	SigningAlgorithmRS384
	SigningAlgorithmRS512
	SigningAlgorithmES256
	SigningAlgorithmES384
	SigningAlgorithmES512
	SigningAlgorithmPS256
	SigningAlgorithmPS384
	SigningAlgorithmPS512
	SigningAlgorithmEdDSA
)

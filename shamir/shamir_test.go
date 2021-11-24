package shamir

import (
	"fmt"
	"math/big"
	"testing"
)

func TestEvalPoly(t *testing.T) {
	coeffs := []*big.Int{big.NewInt(4), big.NewInt(4), big.NewInt(1)}
	r := EvalPoly(coeffs, big.NewInt(4), big.NewInt(7))
	fmt.Println(r.String())
}

func TestGenRandPoly(t *testing.T) {
	coeffs := GenRandPoly(3, big.NewInt(3), big.NewInt(7))

	for _, c := range coeffs {
		fmt.Println(c)
	}
}

func TestAll(test *testing.T) {
	p := big.NewInt(7)
	t := uint64(3)
	s := big.NewInt(6)
	coeffs := GenRandPoly(t, s, p)
	shares := GenShares(coeffs, 5, p)

	recShares := []Share{shares[0], shares[2], shares[4]}
	sRec := Reconstruct(recShares, p)

	fmt.Println(sRec)
}

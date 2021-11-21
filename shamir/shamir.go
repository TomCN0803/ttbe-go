package shamir

import (
	"crypto/rand"
	"math/big"
)

type Share struct {
	X, Y *big.Int
}

// GenRandPoly generate a random Shamir secret sharing polynomial
// modulo p of secret with degree t.
func GenRandPoly(t uint64, secret, p *big.Int) []*big.Int {
	coeffs := make([]*big.Int, 0, t)
	coeffs = append(coeffs, secret)
	for i := uint64(0); i < t-1; i++ {
		c, _ := rand.Int(rand.Reader, p)
		coeffs = append(coeffs, c)
	}

	return coeffs
}

// EvalPoly return the value modulo p of the polynomial
// with coefficients of coeffs at x.
func EvalPoly(coeffs []*big.Int, x, p *big.Int) *big.Int {
	r, xi := big.NewInt(0), big.NewInt(1)
	for _, c := range coeffs {
		tmp := new(big.Int).Mul(c, xi)
		tmp.Mod(tmp, p)
		r.Add(r, tmp)
		r.Mod(r, p)
		xi.Mul(xi, x)
	}
	r.Mod(r, p)

	return r
}

// GenShares generate n shares through polynomial coeffs.
func GenShares(coeffs []*big.Int, n uint64, p *big.Int) []Share {
	shares := make([]Share, 0, n)
	for i := uint64(1); i <= n; i++ {
		x := big.NewInt(int64(i))
		y := EvalPoly(coeffs, x, p)
		shares = append(shares, Share{x, y})
	}

	return shares
}

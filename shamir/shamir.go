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

// Reconstruct the secret with given shares.
func Reconstruct(shares []Share, p *big.Int) *big.Int {
	res := big.NewInt(0)
	xs := make([]*big.Int, 0, len(shares))

	for _, share := range shares {
		xs = append(xs, share.X)
	}

	for _, share := range shares {
		x, y := share.X, share.Y
		lag := LagCoeff(x, xs, p)
		lag.Mul(lag, y)
		res.Add(res, lag)
	}

	return res
}

// LagCoeff get the lagrange coefficient of share x.
func LagCoeff(xk *big.Int, xs []*big.Int, p *big.Int) *big.Int {
	res := big.NewInt(1)
	for _, x := range xs {
		if xk.CmpAbs(x) != 0 {
			den := new(big.Int).Sub(xk, x)
			den.Mod(den, p)
			denInv := invMod(den, p)
			res.Mul(res, denInv)
			res.Mod(res, p)
		}
	}

	return res
}

// invMod find the inverse of a mod p
func invMod(a, p *big.Int) *big.Int {
	res := new(big.Int).Exp(a, new(big.Int).Sub(p, big.NewInt(2)), p)
	res.Mod(res, p)

	return res
}

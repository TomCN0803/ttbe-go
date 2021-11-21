package ttbe

import (
	"crypto/rand"
	"math/big"
	"ttbe-go/shamir"

	bn "golang.org/x/crypto/bn256"
)

// TPK TTBE公钥
type TPK struct {
	H1, U1, V1, W1, Z1 *bn.G1
	H2, U2, V2, W2, Z2 *bn.G2
}

// TSK TTBE私钥
type TSK struct {
	index uint64
	U, V  *big.Int
}

// TVK TTBE验证密钥
type TVK struct {
	index uint64
	U, V  *bn.G2
}

// SetUp TTBE初始化
func SetUp(n, t uint64) (TPK, []TSK, []TVK) {
	var tpk TPK
	tsks := make([]TSK, 0, n)
	tvks := make([]TVK, 0, n)

	h, _ := rand.Int(rand.Reader, bn.Order)
	w, _ := rand.Int(rand.Reader, bn.Order)
	z, _ := rand.Int(rand.Reader, bn.Order)

	// u is the shamir secret of u_1 ... u_n
	// v is the shamir secret of v_1 ... v_n
	// tsk is the shamir secret of tsk_1=(u_1, v_1) ... tsk_n=(u_n, v_n)
	u, _ := rand.Int(rand.Reader, bn.Order)
	v, _ := rand.Int(rand.Reader, bn.Order)
	polyU := shamir.GenRandPoly(t, u, bn.Order)
	polyV := shamir.GenRandPoly(t, v, bn.Order)
	us := shamir.GenShares(polyU, n, bn.Order)
	vs := shamir.GenShares(polyV, n, bn.Order)

	H1, H2 := new(bn.G1).ScalarBaseMult(h), new(bn.G2).ScalarBaseMult(h)
	U1, U2 := new(bn.G1).ScalarMult(H1, u), new(bn.G2).ScalarMult(H2, u)
	vInv := invMod(v, bn.Order) // get the inverse of v i.e. vInv
	V1, V2 := new(bn.G1).ScalarMult(U1, vInv), new(bn.G2).ScalarMult(U2, vInv)
	W1, W2 := new(bn.G1).ScalarMult(H1, w), new(bn.G2).ScalarMult(H2, w)
	Z1, Z2 := new(bn.G1).ScalarMult(V1, z), new(bn.G2).ScalarMult(V2, z)

	for i := uint64(0); i < n; i++ {
		usi, vsi := us[i], vs[i]
		tsks = append(tsks, TSK{i + 1, usi.Y, vsi.Y})
		tvkUi := new(bn.G2).ScalarMult(H2, usi.Y)
		tvkVi := new(bn.G2).ScalarMult(V2, vsi.Y)
		tvks = append(tvks, TVK{i + 1, tvkUi, tvkVi})
	}
	tpk = TPK{H1, U1, V1, W1, Z1, H2, U2, V2, W2, Z2}

	return tpk, tsks, tvks
}

// invMod find the inverse of a modulo p
func invMod(a, p *big.Int) *big.Int {
	return new(big.Int).Exp(a, new(big.Int).Sub(p, big.NewInt(2)), p)
}

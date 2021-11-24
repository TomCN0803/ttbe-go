package ttbe

import (
	"crypto/rand"
	"fmt"
	bn "golang.org/x/crypto/bn256"
	"math/big"
	"testing"
)

func TestSetUp(t *testing.T) {
	tpk, tsks, tvks := SetUp(5, 3)
	fmt.Println(tpk)
	for _, tsk := range tsks {
		fmt.Println(tsk)
	}

	for _, tvk := range tvks {
		fmt.Println(tvk)
	}
}

func TestInvMod(t *testing.T) {
	res := invMod(big.NewInt(2), big.NewInt(11))
	fmt.Println(res.String())
}

func TestTTBE(t *testing.T) {
	tpk, tsks, tvks := SetUp(5, 3)
	tag := big.NewInt(8)

	_, M, _ := bn.RandomG1(rand.Reader)
	fmt.Printf("明文M：%s.\n", M.String())

	c := Encrypt(tpk, tag, M)
	r1 := VerCttbe(tpk, tag, c)
	fmt.Printf("密文c：%v.\n密文是否有效：%v.\n", c, r1)

	ac1, _ := ShareDec(tpk, tsks[0], tag, c)
	ac3, _ := ShareDec(tpk, tsks[2], tag, c)
	ac5, _ := ShareDec(tpk, tsks[4], tag, c)
	acs := []*AudClue{ac1, ac3, ac5}

	for _, ac := range acs {
		tvk := tvks[ac.index-1]
		r := VerAudClue(tpk, tvk, tag, c, ac)
		fmt.Printf("审计线索%d：%v\t 有效性：%v.\n", ac.index, ac, r)
	}

	MRecv, _ := Combine(acs, c)
	correct := M.String() == MRecv.String()
	fmt.Printf("恢复出的结果MRecv：%v，是否正确：%v.\n", MRecv, correct)
}

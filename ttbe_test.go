package ttbe

import (
	"fmt"
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

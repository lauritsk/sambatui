package invariant

import (
	"math"
	"testing"
)

func TestContractsRemainEnabled(t *testing.T) {
	Require(true, "valid")
	if Next(0) != 1 || Next(math.MaxUint64-1) != math.MaxUint64 {
		t.Fatal("generation boundary changed")
	}
	for _, operation := range []func(){
		func() { Require(false, "invalid") },
		func() { Next(math.MaxUint64) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("programmer contract did not panic")
				}
			}()
			operation()
		}()
	}
}

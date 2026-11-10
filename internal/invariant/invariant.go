// Package invariant checks programmer contracts in every build. External input
// must be validated with ordinary errors before it reaches these contracts.
package invariant

import "math"

func Require(condition bool, message string) {
	if !condition {
		panic(message)
	}
}

// Next prevents a wrapped request or connection generation from accepting stale
// asynchronous results. Exhaustion is a programmer/lifetime error, not a retry.
func Next(value uint64) uint64 {
	Require(value < math.MaxUint64, "generation exhausted")
	result := value + 1
	Require(result > value, "generation must increase")
	return result
}

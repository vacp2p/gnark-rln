package rln

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TODO: get kats for other curves

func TestRlnCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var rlnCircuit RlnCircuit

	var identityPathIndex [20]frontend.Variable
	for i := 0; i < 20; i++ {
		var direction frontend.Variable
		if i%2 == 0 {
			direction = frontend.Variable(1)
		} else {
			direction = frontend.Variable(0)
		}
		identityPathIndex[i] = direction
	}

	var pathElements [20]frontend.Variable
	for i := 0; i < 20; i++ {
		pathElements[i] = frontend.Variable(10)
	}

	assert.ProverSucceeded(&rlnCircuit, &RlnCircuit{
		X:                 frontend.Variable(10),
		ExternalNullifier: frontend.Variable(10),
		IdentitySecret:    frontend.Variable(10),
		MessageId:         frontend.Variable(10),
		UserMessageLimit:  frontend.Variable(20),
		PathElements:      pathElements,
		IdentityPathIndex: identityPathIndex,
		Y:                 frontend.Variable(0),
		Root:              frontend.Variable(0),
		Nullifier:         frontend.Variable(0),
	})

}

package rln

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark/test"
)

// TODO: get kats for other curves

func TestRlnCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var rlnCircuit RlnCircuit
	identityPathIndex := [20]frontend.Variable{
		1,
		1,
		1,
		0,
		1,
		0,
		1,
		0,
		1,
		0,
		1,
		0,
		0,
		0,
		0,
		0,
		1,
		1,
		1,
		0,
	}

	curves := ecc.Implemented()
	for _, curve := range curves {
		switch curve {
		case ecc.BN254:
			assert.ProverSucceeded(&rlnCircuit, &RlnCircuit{
				X:                 frontend.Variable(GetBn254X()),
				ExternalNullifier: frontend.Variable(GetBn254ExternalNullifier()),
				IdentitySecret:    frontend.Variable(GetBn254IdentitySecret()),
				MessageId:         frontend.Variable(1),
				UserMessageLimit:  frontend.Variable(100),
				PathElements:      GetBn254PathElements(),
				IdentityPathIndex: identityPathIndex,
				Y:                 frontend.Variable(GetBn254Y()),
				Root:              frontend.Variable(GetBn254Root()),
				Nullifier:         frontend.Variable(GetBn254Nullifier()),
			}, test.WithCurves(ecc.BN254))
		case ecc.BLS12_377:
			assert.ProverSucceeded(&rlnCircuit, &RlnCircuit{
				X:                 frontend.Variable(GetBls12_377X()),
				ExternalNullifier: frontend.Variable(GetBls12_377ExternalNullifier()),
				IdentitySecret:    frontend.Variable(GetBls12_377IdentitySecret()),
				MessageId:         frontend.Variable(1),
				UserMessageLimit:  frontend.Variable(100),
				PathElements:      GetBls12_377PathElements(),
				IdentityPathIndex: identityPathIndex,
				Y:                 frontend.Variable(GetBls12_377Y()),
				Root:              frontend.Variable(GetBls12_377Root()),
				Nullifier:         frontend.Variable(GetBls12_377Nullifier()),
			}, test.WithCurves(ecc.BLS12_377))
		default:
			continue
		}
	}

}

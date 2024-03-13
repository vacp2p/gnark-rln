package rln

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// Circuit defines a simple circuit
// x**3 + x + 5 == y
type RlnCircuit struct {
	X                 frontend.Variable     `gnark:"x, public"`                 // message hash
	ExternalNullifier frontend.Variable     `gnark:"externalNullifier, public"` // external nullifier
	IdentitySecret    frontend.Variable     `gnark:"identitySecret,secret"`     // identity secret
	MessageId         frontend.Variable     `gnark:"messageId,secret"`          // message id
	UserMessageLimit  frontend.Variable     `gnark:"userMessageLimit,secret"`   // user message limit
	PathElements      [20]frontend.Variable `gnark:"pathElements,secret"`       // path elements
	IdentityPathIndex [20]frontend.Variable `gnark:"identityPathIndex,secret"`  // identity path index
	Y                 frontend.Variable     `gnark:"y,public"`
	Root              frontend.Variable     `gnark:"root, public"`
	Nullifier         frontend.Variable     `gnark:"nullifier, public"`
}

func (circuit RlnCircuit) Define(api frontend.API) error {
	identity_commitment := Poseidon(api, []frontend.Variable{circuit.IdentitySecret})
	api.AssertIsEqual(identity_commitment, identity_commitment)
	rate_commitment := Poseidon(api, []frontend.Variable{identity_commitment, circuit.UserMessageLimit})
	api.AssertIsEqual(rate_commitment, rate_commitment)

	levels := len(circuit.IdentityPathIndex)
	hashes := make([]frontend.Variable, levels+1)

	hashes[0] = rate_commitment
	for i := 0; i < levels; i++ {
		api.AssertIsBoolean(circuit.IdentityPathIndex[i])
		left_hash := Poseidon(api, []frontend.Variable{hashes[i], circuit.PathElements[i]})
		right_hash := Poseidon(api, []frontend.Variable{circuit.PathElements[i], hashes[i]})
		hashes[i+1] = api.Select(circuit.IdentityPathIndex[i], right_hash, left_hash)
	}
	root := hashes[levels]
	api.AssertIsEqual(root, circuit.Root)

	rangeChecker := rangecheck.New(api)
	rangeChecker.Check(circuit.MessageId, 16)
	api.AssertIsLessOrEqual(circuit.MessageId, circuit.UserMessageLimit)

	a1 := Poseidon(api, []frontend.Variable{circuit.IdentitySecret, circuit.ExternalNullifier, circuit.MessageId})
	y := api.Add(circuit.IdentitySecret, api.Mul(a1, circuit.X))
	api.AssertIsEqual(y, circuit.Y)

	nullifier := Poseidon(api, []frontend.Variable{a1})
	api.AssertIsEqual(nullifier, circuit.Nullifier)

	return nil
}

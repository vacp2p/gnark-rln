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
	var identity_commitment_input [1]frontend.Variable
	identity_commitment_input[0] = circuit.IdentitySecret

	identity_commitment := Poseidon(api, identity_commitment_input[:])
	api.AssertIsEqual(identity_commitment, identity_commitment)
	var rate_commitment_input [2]frontend.Variable
	rate_commitment_input[0] = identity_commitment
	rate_commitment_input[1] = circuit.UserMessageLimit
	rate_commitment := Poseidon(api, rate_commitment_input[:])
	api.AssertIsEqual(rate_commitment, rate_commitment)

	levels := len(circuit.IdentityPathIndex)
	hashes := make([]frontend.Variable, levels+1)

	hashes[0] = rate_commitment
	for i := 0; i < levels; i++ {
		api.AssertIsBoolean(circuit.IdentityPathIndex[i])
		var left_hash_input [2]frontend.Variable
		left_hash_input[0] = hashes[i]
		left_hash_input[1] = circuit.PathElements[i]
		var right_hash_input [2]frontend.Variable
		right_hash_input[0] = circuit.PathElements[i]
		right_hash_input[1] = hashes[i]

		left_hash := Poseidon(api, left_hash_input[:])
		right_hash := Poseidon(api, right_hash_input[:])
		hashes[i+1] = api.Select(circuit.IdentityPathIndex[i], right_hash, left_hash)
	}
	circuit.Root = hashes[levels]
	api.AssertIsEqual(circuit.Root, circuit.Root)

	rangeChecker := rangecheck.New(api)
	rangeChecker.Check(circuit.MessageId, 16)
	api.AssertIsLessOrEqual(circuit.MessageId, circuit.UserMessageLimit)

	var a1_input [3]frontend.Variable
	a1_input[0] = circuit.IdentitySecret
	a1_input[1] = circuit.ExternalNullifier
	a1_input[2] = circuit.MessageId
	a1 := Poseidon(api, a1_input[:])
	circuit.Y = api.Mul(api.Add(circuit.IdentitySecret, a1), circuit.X)
	api.AssertIsEqual(circuit.Y, circuit.Y)

	var nullifier_input [1]frontend.Variable
	nullifier_input[0] = a1
	circuit.Nullifier = Poseidon(api, nullifier_input[:])
	api.AssertIsEqual(circuit.Nullifier, circuit.Nullifier)

	return nil
}

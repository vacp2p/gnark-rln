package rln

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

type RlnCircuit struct {
	X                 frontend.Variable     `gnark:"x, public"`                 // message hash
	ExternalNullifier frontend.Variable     `gnark:"externalNullifier, public"` // external nullifier
	Epoch             frontend.Variable     `gnark:"epoch, secret"`             // epoch
	RlnIdentifer      frontend.Variable     `gnark:"rlnIdentifier, public"`     // rln identifier
	IdentitySecret    frontend.Variable     `gnark:"identitySecret,secret"`     // identity secret
	MessageId         frontend.Variable     `gnark:"messageId,secret"`          // message id
	UserMessageLimit  frontend.Variable     `gnark:"userMessageLimit,secret"`   // user message limit
	UserEpochLimit    frontend.Variable     `gnark:"userEpochLimit,secret"`     // user epoch limit
	EpochQuotient     frontend.Variable     `gnark:"epochQuotient,secret"`      // epoch quotient
	PathElements      [20]frontend.Variable `gnark:"pathElements,secret"`       // path elements
	IdentityPathIndex [20]frontend.Variable `gnark:"identityPathIndex,secret"`  // identity path index
	Y                 frontend.Variable     `gnark:"y,public"`
	Root              frontend.Variable     `gnark:"root, public"`
	Nullifier         frontend.Variable     `gnark:"nullifier, public"`
}

func (circuit RlnCircuit) Define(api frontend.API) error {
	identity_commitment := Poseidon(api, []frontend.Variable{circuit.IdentitySecret})
	rate_commitment := Poseidon(api, []frontend.Variable{identity_commitment, circuit.UserMessageLimit, circuit.UserEpochLimit})

	external_nullifier := Poseidon(api, []frontend.Variable{circuit.Epoch, circuit.RlnIdentifer})
	api.AssertIsEqual(external_nullifier, circuit.ExternalNullifier)

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
	// messageId can be max 16 bits, i.e 0..65535
	rangeChecker.Check(circuit.MessageId, 16)
	// messageId should be less than userMessageLimit
	api.AssertIsLessOrEqual(circuit.MessageId, circuit.UserMessageLimit)

	rangeChecker = rangecheck.New(api)
	// epoch must be less than 2^64 (to avoid year 2038 problem)
	rangeChecker.Check(circuit.Epoch, 64)

	rangeChecker = rangecheck.New(api)
	// userEpochLimit can be max 12 bits, i.e 0..4095
	rangeChecker.Check(circuit.UserEpochLimit, 12)
	// userEpochLimit should be less than 3600, in seconds is 1 hour
	api.AssertIsLessOrEqual(circuit.UserEpochLimit, 3600)

	// we also need to ensure that the provided epoch is a multiple of the UserEpochLimit,
	// since UserEpochLimit defines the precision of the epoch,
	// i.e if UserEpochLimit is 1, then the epoch is unix timestamp in seconds,
	// if UserEpochLimit is 60, then the epoch is unix timestamp per 60 seconds, etc., i.e unix_epoch_timestamp % UserEpochLimit == 0
	// constraints here to ensure that the provided epoch is a multiple of the UserEpochLimit
	api.AssertIsLessOrEqual(circuit.UserEpochLimit, circuit.Epoch)                           // we need this since UserEpochLimit may be < 3600, and provided epoch also may be < 3600
	api.AssertIsLessOrEqual(circuit.EpochQuotient, circuit.UserEpochLimit)                   // we need this to ensure that no overflowing value is provided
	api.AssertIsEqual(circuit.Epoch, api.Mul(circuit.EpochQuotient, circuit.UserEpochLimit)) // we need this to ensure proper off-circuit computation of the epoch quotient
	// api.AssertIsEqual(circuit.EpochQuotient, api.Div(circuit.Epoch, circuit.UserEpochLimit)) // redundant

	a1 := Poseidon(api, []frontend.Variable{circuit.IdentitySecret, circuit.ExternalNullifier, circuit.MessageId})
	y := api.Add(circuit.IdentitySecret, api.Mul(a1, circuit.X))
	api.AssertIsEqual(y, circuit.Y)

	nullifier := Poseidon(api, []frontend.Variable{a1})
	api.AssertIsEqual(nullifier, circuit.Nullifier)

	return nil
}

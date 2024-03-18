package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	rln "github.com/rymnc/gnark-rln/rln"
)

func main() {
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

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rln.RlnCircuit{})
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	assignment := &rln.RlnCircuit{
		X:                 frontend.Variable(rln.GetBn254X()),
		ExternalNullifier: frontend.Variable(rln.GetBn254ExternalNullifier()),
		IdentitySecret:    frontend.Variable(rln.GetBn254IdentitySecret()),
		Epoch:             frontend.Variable(240),
		EpochQuotient:     frontend.Variable(2),
		RlnIdentifer:      frontend.Variable(1),
		UserEpochLimit:    frontend.Variable(120),
		MessageId:         frontend.Variable(1),
		UserMessageLimit:  frontend.Variable(100),
		PathElements:      rln.GetBn254PathElements(),
		IdentityPathIndex: identityPathIndex,
		Y:                 frontend.Variable(rln.GetBn254Y()),
		Root:              frontend.Variable(rln.GetBn254Root()),
		Nullifier:         frontend.Variable(rln.GetBn254Nullifier()),
	}

	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}

	verifyWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, verifyWitness)

	if err != nil {
		print(err.Error())
	}
}

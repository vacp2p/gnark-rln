package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

	rawPathElements := [20]string{
		"14082964758224722211945379872337797638951236517417253447686770846170014042825",
		"6628418579821163687428454604867534487917867918886059133241840211975892987309",
		"12745863228198753394445659605634840709296716381893463421165313830643281758511",
		"56118267389743063830320351452083247040583061493621478539311100137113963555",
		"3648731943306935051357703221473866306053186513730785325303257057776816073765",
		"10548621390442503192989374711060717107954536293658152583621924810330521179016",
		"11741160669079729961275351458682156164905457324981803454515784688429276743441",
		"17165464309215350864730477596846156251863702878546777829650812432906796008534",
		"18947162586829418653666557598416458949428989734998924978331450666032720066913",
		"8809427088917589399897132358419395928548406347152047718919154153577297139202",
		"6261460226929242970747566981077801929281729646713842579109271945192964422300",
		"13871468675790284383809887052382100311103716176061564908030808887079542722597",
		"10413964486611723004584705484327518190402370933255450052832412709168190985805",
		"3978387560092078849178760154060822400741873818692524912249877867958842934383",
		"14014915591348694328771517896715085647041518432952027841088176673715002508448",
		"17680675606519345547327984724173632294904524423937145835611954334756161077843",
		"17107175244885276119916848057745382329169223109661217238296871427531065458152",
		"18326186549441826262593357123467931475982067066825042001499291800252145875109",
		"7043961192177345916232559778383741091053414803377017307095275172896944935996",
		"2807630271073553218355393059254209097448243975722083008310815929736065268921",
	}

	pathElements := [20]frontend.Variable{}
	// iterate over pathElements and replace with fr.Modulus().SetString("...") for eac, 10h element
	for i := 0; i < len(pathElements); i++ {
		x, ret := fr.Modulus().SetString(rawPathElements[i], 10)
		if ret != true {
			panic(ret)
		}
		pathElements[i] = frontend.Variable(x)
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rln.RlnCircuit{})
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	x, ret := fr.Modulus().SetString("20645213238265527935869146898028115621427162613172918400241870500502509785943", 10)
	if ret != true {
		panic(ret)
	}

	external_nullifier, ret := fr.Modulus().SetString("21074405743803627666274838159589343934394162804826017440941339048886754734203", 10)
	if ret != true {
		panic(ret)
	}

	identity_secret, ret := fr.Modulus().SetString("2301650865650889795878889082892690584512243988708213561328369865554257051708", 10)
	if ret != true {
		panic(ret)
	}

	y, ret := fr.Modulus().SetString("16401008481486069296141645075505218976370369489687327284155463920202585288271", 10)
	if ret != true {
		panic(ret)
	}

	nullifier, ret := fr.Modulus().SetString("9102791780887227194595604713537772536258726662792598131262022534710887343694", 10)
	if ret != true {
		panic(ret)
	}

	root, ret := fr.Modulus().SetString("8502402278351299594663821509741133196466235670407051417832304486953898514733", 10)
	if ret != true {
		panic(ret)
	}

	assignment := &rln.RlnCircuit{
		X:                 frontend.Variable(x),
		ExternalNullifier: frontend.Variable(external_nullifier),
		IdentitySecret:    frontend.Variable(identity_secret),
		MessageId:         frontend.Variable(1),
		UserMessageLimit:  frontend.Variable(100),
		PathElements:      pathElements,
		IdentityPathIndex: identityPathIndex,
		Y:                 frontend.Variable(y),
		Root:              frontend.Variable(root),
		Nullifier:         frontend.Variable(nullifier),
	}

	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}

	raw := &rln.RlnCircuit{
		X:                 frontend.Variable(x),
		ExternalNullifier: frontend.Variable(external_nullifier),
		Y:                 frontend.Variable(y),
		Root:              frontend.Variable(root),
		Nullifier:         frontend.Variable(nullifier),
	}
	verifyWitness, err := frontend.NewWitness(raw, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, verifyWitness)

	if err != nil {
		print(err.Error())
	}
}

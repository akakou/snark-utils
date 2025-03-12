package snarkutils

import (
	"github.com/akakou/snark-utils/primitives/hash/circuit"
	"github.com/akakou/snark-utils/primitives/hash/witness"
	"github.com/consensys/gnark-crypto/hash"
)

// var NewCircuitHash = circuit.NewPoseidon
// var NewCommitHash = poseidon.NewPoseidon
// var CommitHash = commit.PoseidonHash

var NewCircuitHash = circuit.NewMIMC
var NewCommitHash = NewCommitHashBase.New
var CommitHash = witness.MimcHash(NewCommitHashBase)

var NewCommitHashBase = hash.MIMC_BLS12_381

var CircuitHash = circuit.HashMaker(NewCircuitHash)

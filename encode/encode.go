package encode

import (
	snark "github.com/akakou/snark-utils"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

func EncodeCircuit(circuit constraint.ConstraintSystem) ([]byte, error) {
	return EncodeWithWriteTo(circuit)
}

func DecodeCircuit(circuitBytes []byte) (constraint.ConstraintSystem, error) {
	cs := groth16.NewCS(snark.EcCurve)
	err := DecodeWithReadFrom(circuitBytes, cs)
	return cs, err
}

func EncodeProverKey(proveKey groth16.ProvingKey) ([]byte, error) {
	return EncodeWithWriteDump(proveKey)
}

func DecodeProverKey(proveKeyBytes []byte) (groth16.ProvingKey, error) {
	proveKey := groth16.NewProvingKey(snark.EcCurve)
	err := DecodeWithReadDump(proveKeyBytes, proveKey)
	return proveKey, err
}

func EncodeVerifierKey(verifyKey groth16.VerifyingKey) ([]byte, error) {
	return EncodeWithWriteTo(verifyKey)
}

func DecodeVerifierKey(verifyKeyBytes []byte) (groth16.VerifyingKey, error) {
	verifyKey := groth16.NewVerifyingKey(snark.EcCurve)
	err := DecodeWithReadFrom(verifyKeyBytes, verifyKey)
	return verifyKey, err

}

func EncodeProof(proof groth16.Proof) ([]byte, error) {
	return EncodeWithWriteTo(proof)
}

func DecodeProof(proofBytes []byte) (groth16.Proof, error) {
	proof := groth16.NewProof(snark.EcCurve)
	err := DecodeWithReadFrom(proofBytes, proof)
	return proof, err
}

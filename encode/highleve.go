package encode

import snark "github.com/akakou/snark-utils"

type HighLevelSnarkProver struct {
	ConstraintSystem []byte
	ProveKey         []byte
}

func (prover HighLevelSnarkProver) ToSnarkProver() (*snark.SnarkProver, error) {
	cs, err := DecodeCircuit(prover.ConstraintSystem)
	if err != nil {
		return nil, err
	}

	proveKeyObj, err := DecodeProverKey(prover.ProveKey)
	if err != nil {
		return nil, err
	}

	proverObj := snark.SnarkProver{
		ConstraintSystem: cs,
		ProveKey:         proveKeyObj,
	}

	return &proverObj, nil
}

func (highl *HighLevelSnarkProver) FromSnarkProver(prover *snark.SnarkProver) error {
	circuitBytes, err := EncodeCircuit(prover.ConstraintSystem)
	if err != nil {
		return err
	}

	proverKeyBytes, err := EncodeProverKey(prover.ProveKey)
	if err != nil {
		return err
	}

	highl.ProveKey = proverKeyBytes
	highl.ConstraintSystem = circuitBytes

	return nil
}

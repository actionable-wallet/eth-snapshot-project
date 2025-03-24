package utils

import (
	"github.com/alinush/go-mcl"
)

const (
	SLICING_INTERVAL = 5  // Create a snapshot every 5 rounds
	ADDR_OFFSET  int = 43
	NONCE_OFFSET int = 22
	VAL_OFFSET   int = 1
)

// Slice represents a blockchain state slice containing account states, proofs, and commitment
type Slice struct {
	// State vector containing all account states
	// Each account state contains: address(21 bits), nonce(21 bits), value(21 bits), and padding(1 bit)
	State []mcl.Fr

	// Proof vector for all accounts
	// Each account corresponds to a proof path
	Proofs [][]mcl.G1

	// Commitment value of the state
	Commitment mcl.G1
}

// StateInfo stores vectors used in each round
type StateInfo struct {
	StateIndex  uint64
	IndexVec    []uint64
	ProofVec    [][]mcl.G1
	DeltaVec    []mcl.Fr
	ValueVec    []mcl.Fr
	Commitment  mcl.G1
}
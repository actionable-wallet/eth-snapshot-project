package utils

import (
	"github.com/alinush/go-mcl"
)

const (
	SLICING_INTERVAL = 5  // Create a snapshot every 5 rounds
	ADDR_OFFSET  int = 43
	NONCE_OFFSET int = 22
	VAL_OFFSET   int = 1
	PAD_OFFSET   int = 0
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

// TransactionRecord represents a single transaction in the system
type TransactionRecord struct {
	StateIndex        int    	// The round number when this transaction occurred
	AccountIndex uint64 	// The account that this transaction belongs to
	ValueDelta   int    	// The change in value (can be positive or negative)
	Nonce        int64  	// Transaction sequence number for the account
}

// StateProofResult stores the result of state proof
type StateProofResult struct {
	State     []mcl.Fr    // State S_i
	Accounts  []mcl.Fr    // Account information a_I^i
	Proof     []mcl.G1    // Proof π
	Delta     []mcl.Fr    // Account delta a_I^δ
	BaseProof []mcl.G1    // Base proof π_I^k
}
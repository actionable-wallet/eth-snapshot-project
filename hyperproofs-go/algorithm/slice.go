package algorithm

import (
	"strconv"

	"github.com/alinush/go-mcl"
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

// NewSlice creates a new slice
func NewSlice(state []mcl.Fr, proofs [][]mcl.G1, commitment mcl.G1) *Slice {
	return &Slice{
		State:           state,
		Proofs:          proofs,
		Commitment:      commitment,
	}
}

// ExtractField extracts a specific field (address, nonce, or value) from an account state
func (s *Slice) ExtractField(accountIndex uint64, offset int) int64 {
	if accountIndex >= uint64(len(s.State)) {
		return 0
	}

	// Create mask: 21 bits of 1s, then shift left by offset
	mask := int64((1 << 21) - 1) << offset

	// Get the complete value of the account state
	val, err := strconv.ParseInt(s.State[accountIndex].GetString(10), 10, 64)
	if err != nil {
		return 0
	}

	// Apply mask and shift right to correct position
	return (val & mask) >> offset
}

// GetAccountState retrieves the state of a specified account
func (s *Slice) GetAccountState(accountIndex uint64) *mcl.Fr {
	if accountIndex >= uint64(len(s.State)) {
		return nil
	}
	return &s.State[accountIndex]
}

// GetAccountProof retrieves the proof of a specified account
func (s *Slice) GetAccountProof(accountIndex uint64) []mcl.G1 {
	if accountIndex >= uint64(len(s.Proofs)) {
		return nil
	}
	return s.Proofs[accountIndex]
}
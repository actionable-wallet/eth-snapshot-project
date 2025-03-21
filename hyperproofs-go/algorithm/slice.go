package algorithm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/alinush/go-mcl"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

const (
	SNAPSHOT_INTERVAL = 5  // Create a snapshot every 5 rounds
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

// This function prints the information of all slices
func PrintAllSliceInfo(vcs *vc.VCS, snapshots []*Slice) {
	fmt.Println("\n=== Available Snapshots ===")
	for i, snapshot := range snapshots {
		fmt.Printf("\nSnapshot %d: Commitment = %v\n", i*SNAPSHOT_INTERVAL, snapshot.Commitment)
		fmt.Println(strings.Repeat("-", 80))

		for j := uint64(0); j < vcs.N; j++ {
			addr := snapshot.ExtractField(j, ADDR_OFFSET)
			nonce := snapshot.ExtractField(j, NONCE_OFFSET)
			value := snapshot.ExtractField(j, VAL_OFFSET)

			fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n",
				j, addr, nonce, value)
		}
		fmt.Println(strings.Repeat("-", 80))
	}
}

func PrintSliceInfo(vcs *vc.VCS, snapshot *Slice) {
	fmt.Println(strings.Repeat("-", 80))
	for i := uint64(0); i < vcs.N; i++ {
		addr := snapshot.ExtractField(i, ADDR_OFFSET)
		nonce := snapshot.ExtractField(i, NONCE_OFFSET)
		value := snapshot.ExtractField(i, VAL_OFFSET)
		
		fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n", 
			i, addr, nonce, value)
	}
	fmt.Println(strings.Repeat("-", 80))
}
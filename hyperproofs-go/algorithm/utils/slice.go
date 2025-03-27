package utils

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/alinush/go-mcl"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

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
		fmt.Printf("\nSnapshot %d: Commitment = %v\n", i*SLICING_INTERVAL, snapshot.Commitment)
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

// This function prints the information of an account
func PrintAccountInfo(vcs *vc.VCS, snapshot *Slice) {
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

// This function finds the nearest slice to the target state
func FindCLoestSlice(vcs *vc.VCS, slices []*Slice, targetState uint64) (Slice, uint64) {
	PrintAllSliceInfo(vcs, slices)

	// Find the nearest slice index
	sliceIndex := (targetState / SLICING_INTERVAL) * SLICING_INTERVAL

	fmt.Printf("\nRecovering state %d from the slice at state %d...\n", targetState, sliceIndex)

	// Get the slice
	closestSlice := *slices[sliceIndex / SLICING_INTERVAL]

	// Print account information
	fmt.Printf("\nInitial account information at state %d:\n", sliceIndex)
	PrintAccountInfo(vcs, &closestSlice)

	return closestSlice, sliceIndex
}
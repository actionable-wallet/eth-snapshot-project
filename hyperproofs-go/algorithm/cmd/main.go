package main

import (
	"flag"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/algorithm"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

const (
	FOLDER = "../../pkvk-02"
	SNAPSHOT_INTERVAL = 5  // Create a snapshot every 5 rounds
	addrOffset  int = 43
	nonceOffset int = 22
	valOffset   int = 1
)

// RoundInfo stores vectors used in each round
type RoundInfo struct {
	Round       uint64
	IndexVec    []uint64
	ProofVec    [][]mcl.G1
	DeltaVec    []mcl.Fr
	ValueVec    []mcl.Fr
	Commitment  mcl.G1
}

func main() {
	// Initialization of state vector
	transactionRoundNum := flag.Uint64("R", 20, "Number of transaction rounds")
	transactionNum := flag.Uint64("K", 10, "Number of transactions per round")
	stateVecSize := flag.Uint64("N", 4, "State vector size (must be a power of 2)")
	flag.Parse()
	stateVecLevel := uint8(math.Log2(float64(*stateVecSize)))
	mcl.InitFromString("bls12-381")
	vcs, aFr := initializeVCS(stateVecLevel, *stateVecSize, *transactionNum)
	fmt.Println(vc.SEP)
	fmt.Print("Start of Simulation")
	fmt.Println(vc.SEP)

	// Create arrays to store round information and snapshots
	txnData := make([]RoundInfo, *transactionRoundNum + 1)
	snapshots := make([]*algorithm.Slice, 0)

	// Save initial slice
	vcs.OpenAll(aFr)
	initialSlice := algorithm.NewSlice(aFr, getProofs(&vcs, *stateVecSize), vcs.Commit(aFr, uint64(stateVecLevel)))
	snapshots = append(snapshots, initialSlice)
	fmt.Printf("Saved initial state snapshot (Round 0)\n")
	
	// Create a copy of initial state for tracking
	currentState := make([]mcl.Fr, len(aFr))
	copy(currentState, aFr)
	
	// Print initial state
	fmt.Println("\n=== Initial State Information ===")
	for j := uint64(0); j < *stateVecSize; j++ {
		address := initialSlice.ExtractField(j, addrOffset)
		nonce := initialSlice.ExtractField(j, nonceOffset)
		value := initialSlice.ExtractField(j, valOffset)
		fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n",
			j, address, nonce, value)
	}

	// Process each round with new transactions
	for i := uint64(0); i < *transactionRoundNum; i++ {
		fmt.Print(vc.SEP)
		fmt.Printf("\n=== Processing Round %d ===", i+1)
		fmt.Println(vc.SEP)
		
		// Generate new transaction vectors for this round
		indexVec, proofVec, deltaVec, valueVec := algorithm.GenerateTransactionVectors(&vcs, aFr, *transactionNum, *stateVecSize)
		
		// Store round information
		roundInfo := RoundInfo{
			Round:    i + 1,
			IndexVec: make([]uint64, len(indexVec)),
			ProofVec: make([][]mcl.G1, len(proofVec)),
			DeltaVec: make([]mcl.Fr, len(deltaVec)),
			ValueVec: make([]mcl.Fr, len(valueVec)),
		}

		// Deep copy vectors
		copy(roundInfo.IndexVec, indexVec)
		copy(roundInfo.DeltaVec, deltaVec)
		copy(roundInfo.ValueVec, valueVec)
		for j := range proofVec {
			roundInfo.ProofVec[j] = make([]mcl.G1, len(proofVec[j]))
			copy(roundInfo.ProofVec[j], proofVec[j])
		}

		// Apply transactions to current state
		algorithm.UpdateAccount(&vcs, currentState, roundInfo.IndexVec, roundInfo.DeltaVec, int(i+1))

		// Generate and store commitment for this round
		vcs.OpenAll(currentState)
		commitment := vcs.Commit(currentState, uint64(stateVecLevel))
		roundInfo.Commitment = commitment

		txnData[i + 1] = roundInfo
		
		// Print transaction data for this round
		fmt.Printf("\n=== Transaction Data for Round %d ===\n", i+1)
		
		// Group transactions by account
		accountTransactions := make(map[uint64][]int)
		for j, idx := range roundInfo.IndexVec {
			accountTransactions[idx] = append(accountTransactions[idx], j)
		}
		
		// For each account with transactions
		for accountIndex := uint64(0); accountIndex < *stateVecSize; accountIndex++ {
			txList, exists := accountTransactions[accountIndex]
			if !exists {
				continue // Skip accounts without transactions
			}
			
			// Get account state from latest snapshot
			var currentAddress, currentNonce, currentValue int64
			if len(snapshots) > 0 {
				latestSnapshot := snapshots[len(snapshots)-1]
				currentAddress = latestSnapshot.ExtractField(accountIndex, addrOffset)
				currentNonce = latestSnapshot.ExtractField(accountIndex, nonceOffset)
				currentValue = latestSnapshot.ExtractField(accountIndex, valOffset)
			}
			
			fmt.Printf("\n  Account[%d] - Address: %d, Current Nonce: %d, Current Value: %d\n", 
				accountIndex, currentAddress, currentNonce, currentValue)
			fmt.Printf("  Transactions in Round %d:\n", i+1)
			
			// For each transaction affecting this account
			for _, txIndex := range txList {
				// Parse delta (the change being applied)
				deltaVal, err := strconv.ParseInt(roundInfo.DeltaVec[txIndex].GetString(10), 10, 64)
				if err != nil {
					fmt.Printf("    Transaction #%d: Error parsing delta\n", txIndex)
					continue
				}
				
				// Extract fields from delta
				addressChange := (deltaVal >> addrOffset) & ((1 << 21) - 1)
				nonceChange := (deltaVal >> nonceOffset) & ((1 << 21) - 1)
				valueChange := (deltaVal >> valOffset) & ((1 << 21) - 1)
				
				// Parse value (the account state before transaction)
				valueVal, err := strconv.ParseInt(roundInfo.ValueVec[txIndex].GetString(10), 10, 64)
				if err != nil {
					fmt.Printf("    Transaction #%d: Error parsing value\n", txIndex)
					continue
				}
				
				// Extract fields from current state
				beforeAddress := (valueVal >> addrOffset) & ((1 << 21) - 1)
				beforeNonce := (valueVal >> nonceOffset) & ((1 << 21) - 1)
				beforeValue := (valueVal >> valOffset) & ((1 << 21) - 1)
				
				// Calculate after state
				afterAddress := beforeAddress
				if addressChange > 0 {
					afterAddress = addressChange
				}
				afterNonce := beforeNonce + nonceChange
				afterValue := beforeValue + valueChange
				
				fmt.Printf("    Transaction #%d:\n", txIndex)
				fmt.Printf("      - Before Transaction: Address=%d, Nonce=%d, Value=%d\n",
					beforeAddress, beforeNonce, beforeValue)
				fmt.Printf("      - Changes Applied: Nonce +%d, Value +%d\n",
					nonceChange, valueChange)
				fmt.Printf("      - After Transaction: Address=%d, Nonce=%d, Value=%d\n", 
					afterAddress, afterNonce, afterValue)
			}
		}
		
		// Check if this is a snapshot round
		if (i + 1) % SNAPSHOT_INTERVAL == 0 {
			fmt.Printf("\nCreating snapshot for Round %d...\n", i+1)
			
			// Create a new state array for the snapshot
			snapshotState := make([]mcl.Fr, len(currentState))
			copy(snapshotState, currentState)
			
			// Create and save snapshot using the new state array
			vcs.OpenAll(snapshotState)
			snapshot := algorithm.NewSlice(snapshotState, getProofs(&vcs, *stateVecSize), vcs.Commit(snapshotState, uint64(stateVecLevel)))
			snapshots = append(snapshots, snapshot)
			fmt.Printf("Saved state snapshot (Round %d)\n", i + 1)
			
			// Print snapshot content
			fmt.Printf("\n=== Snapshot State at Round %d ===\n", i + 1)
			
			// If there's a previous snapshot, calculate state changes
			var prevSnapshot *algorithm.Slice
			if len(snapshots) > 1 {
				prevSnapshot = snapshots[len(snapshots)-2]
			}
			
			for j := uint64(0); j < *stateVecSize; j++ {
				address := snapshot.ExtractField(j, addrOffset)
				nonce := snapshot.ExtractField(j, nonceOffset)
				value := snapshot.ExtractField(j, valOffset)
				
				fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d", 
					j, address, nonce, value)
				
				// If there's a previous snapshot, show state changes
				if prevSnapshot != nil {
					prevNonce := prevSnapshot.ExtractField(j, nonceOffset)
					prevValue := prevSnapshot.ExtractField(j, valOffset)
					
					nonceDiff := nonce - prevNonce
					valueDiff := value - prevValue
					
					if nonceDiff != 0 || valueDiff != 0 {
						fmt.Printf(" (Changes: Nonce %+d, Value %+d)", nonceDiff, valueDiff)
					}
				}
				fmt.Println()
			}
			fmt.Println(vc.SEP)
		}
	}

	fmt.Println(vc.SEP)
	fmt.Print("End of Simulation")
	fmt.Println(vc.SEP)

	fmt.Println(vc.SEP)
	fmt.Print("Start of Algorithm 1")
	fmt.Println(vc.SEP)

	fmt.Println("\n=== State Recovery Test ===")
	fmt.Print("Enter round number to recover (0-based): ")
	var targetRound uint64
	fmt.Scanf("%d", &targetRound)

	recoveredSlice, snapshotRound := findCLoestSlice(&vcs, snapshots, targetRound)

	// Apply transactions from the snapshot round to the target round
	if targetRound > snapshotRound {
		// snapshotRound is a multiple of SNAPSHOT_INTERVAL
		fmt.Printf("\nApplying transactions from round %d to %d...\n", snapshotRound, targetRound)
		
		if snapshotRound != targetRound {
			for i := snapshotRound + 1; i <= targetRound; i++ {
				fmt.Println("apply transaction from round", i)
				roundInfo := txnData[i]
				algorithm.UpdateAccount(&vcs, recoveredSlice.State, roundInfo.IndexVec, roundInfo.DeltaVec, int(i+1))
			}
		}
	}

	// Generate commitment for the recovered state
	vcs.OpenAll(recoveredSlice.State)
	recoveredCommitment := vcs.Commit(recoveredSlice.State, uint64(stateVecLevel))
	
	// Compare with original commitment
	var originalCommitment mcl.G1
	if targetRound == 0 {
		// For round 0, use the initial slice's commitment
		originalCommitment = snapshots[0].Commitment
	} else {
		// For other rounds, use the commitment from the previous round
		originalCommitment = txnData[targetRound].Commitment
	}
	
	// Compare commitments
	if recoveredCommitment.IsEqual(&originalCommitment) {
		fmt.Println("\nCommitment verification: SUCCESS - Recovered state matches original state")
	} else {
		fmt.Println("\nCommitment verification: FAILED - Recovered state differs from original state")
	}

	// Print the recovered state
	fmt.Printf("\nRecovered State at Round %d:\n", targetRound)
	fmt.Println(strings.Repeat("-", 80))
	for i := uint64(0); i < vcs.N; i++ {
		addr := recoveredSlice.ExtractField(i, addrOffset)
		nonce := recoveredSlice.ExtractField(i, nonceOffset)
		value := recoveredSlice.ExtractField(i, valOffset)
		
		fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n", 
			i, addr, nonce, value)
	}
	fmt.Println(strings.Repeat("-", 80))
}

// This function initializes the VCS and generates a random vector.
func initializeVCS(stateVecLevel uint8, stateVecSize uint64, transactionNum uint64) (vc.VCS, []mcl.Fr) {
	vcs := vc.VCS{}
	vcs.KeyGenLoad(16, stateVecLevel, FOLDER, transactionNum)
	aFr := vc.GenerateVector(stateVecSize)
	vc.SaveVector(stateVecSize, aFr)
	return vcs, aFr
}

// getProofs retrieves proofs for all accounts
func getProofs(vcs *vc.VCS, stateSize uint64) [][]mcl.G1 {
	proofs := make([][]mcl.G1, stateSize)
	for i := uint64(0); i < stateSize; i++ {
		proofs[i] = vcs.GetProofPath(i)
	}
	return proofs
}

func findCLoestSlice(vcs *vc.VCS, snapshots []*algorithm.Slice, targetRound uint64) (algorithm.Slice, uint64) {
	fmt.Println("\n=== Available Snapshots ===")
	for i, snapshot := range snapshots {
		fmt.Printf("\nSnapshot %d: Commitment = %v\n", i*SNAPSHOT_INTERVAL, snapshot.Commitment)
		fmt.Println(strings.Repeat("-", 80))

		for j := uint64(0); j < vcs.N; j++ {
			addr := snapshot.ExtractField(j, addrOffset)
			nonce := snapshot.ExtractField(j, nonceOffset)
			value := snapshot.ExtractField(j, valOffset)

			fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n",
				j, addr, nonce, value)
		}
		fmt.Println(strings.Repeat("-", 80))
	}

	// Find the nearest snapshot
	var snapshotRound uint64
	if targetRound < SNAPSHOT_INTERVAL {
		snapshotRound = 0
	} else if targetRound % SNAPSHOT_INTERVAL == 0 {
		snapshotRound = targetRound
	} else {
		snapshotRound = ((targetRound - 1) / SNAPSHOT_INTERVAL) * SNAPSHOT_INTERVAL
	}

	fmt.Printf("\nRecovering state for round %d from snapshot at round %d...\n", targetRound, snapshotRound)

	// Get the snapshot
	var recoveredSlice algorithm.Slice
	snapshotIndex := snapshotRound / SNAPSHOT_INTERVAL
	recoveredSlice = *snapshots[snapshotIndex]

	// Print initial state from snapshot
	fmt.Printf("\nInitial State from Snapshot at Round %d:\n", snapshotRound)
	fmt.Println(strings.Repeat("-", 80))
	for i := uint64(0); i < vcs.N; i++ {
		addr := recoveredSlice.ExtractField(i, addrOffset)
		nonce := recoveredSlice.ExtractField(i, nonceOffset)
		value := recoveredSlice.ExtractField(i, valOffset)
		
		fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n", 
			i, addr, nonce, value)
	}
	fmt.Println(strings.Repeat("-", 80))
	return recoveredSlice, snapshotRound
}

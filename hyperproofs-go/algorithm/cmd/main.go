package main

import (
	"flag"
	"fmt"
	"math"
	"strconv"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/algorithm/algorithm1"
	"github.com/hyperproofs/hyperproofs-go/algorithm/algorithm2"
	"github.com/hyperproofs/hyperproofs-go/algorithm/utils"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

const (
	FOLDER = "../../pkvk-02"
)

func main() {
	// Initialization of state vector
	transactionRoundNum := flag.Uint64("R", 5, "Number of state transitions")
	transactionNum := flag.Uint64("K", 10, "Number of transactions per state")
	stateVecSize := flag.Uint64("N", 4, "State vector size (must be a power of 2)")
	flag.Parse()
	stateVecLevel := uint8(math.Log2(float64(*stateVecSize)))
	mcl.InitFromString("bls12-381")
	vcs, aFr := initializeVCS(stateVecLevel, *stateVecSize, *transactionNum)
	fmt.Println(vc.SEP)
	fmt.Print("Start of Simulation")
	fmt.Println(vc.SEP)

	// Create arrays to store round information and snapshots
	txnData := make([]utils.StateInfo, *transactionRoundNum + 1)
	snapshots := make([]*utils.Slice, 0)

	// Save initial slice
	vcs.OpenAll(aFr)
	initialSlice := utils.NewSlice(aFr, getProofs(&vcs, *stateVecSize), vcs.Commit(aFr, uint64(stateVecLevel)))
	snapshots = append(snapshots, initialSlice)
	fmt.Printf("Saved initial state snapshot (Round 0)\n")
	
	// Create a copy of initial state for tracking
	currentState := make([]mcl.Fr, len(aFr))
	copy(currentState, aFr)
	
	// Print initial state
	fmt.Println("\n=== Initial State Information ===")
	for j := uint64(0); j < *stateVecSize; j++ {
		address := initialSlice.ExtractField(j, utils.ADDR_OFFSET)
		nonce := initialSlice.ExtractField(j, utils.NONCE_OFFSET)
		value := initialSlice.ExtractField(j, utils.VAL_OFFSET)
		fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n",
			j, address, nonce, value)
	}

	// Process each round with new transactions
	for i := uint64(0); i < *transactionRoundNum; i++ {
		fmt.Print(vc.SEP)
		fmt.Printf("\n=== Processing Round %d ===", i+1)
		fmt.Println(vc.SEP)
		
		// Generate new transaction vectors for this state
		indexVec, proofVec, deltaVec, valueVec := utils.GenerateTransactionVectors(&vcs, aFr, *transactionNum, *stateVecSize)
		
		// Store state information
		stateInfo := utils.StateInfo{
			StateIndex:    i + 1,
			IndexVec: make([]uint64, len(indexVec)),
			ProofVec: make([][]mcl.G1, len(proofVec)),
			DeltaVec: make([]mcl.Fr, len(deltaVec)),
			ValueVec: make([]mcl.Fr, len(valueVec)),
		}

		// Deep copy vectors
		copy(stateInfo.IndexVec, indexVec)
		copy(stateInfo.DeltaVec, deltaVec)
		copy(stateInfo.ValueVec, valueVec)
		for j := range proofVec {
			stateInfo.ProofVec[j] = make([]mcl.G1, len(proofVec[j]))
			copy(stateInfo.ProofVec[j], proofVec[j])
		}

		// Apply transactions to current state
		utils.UpdateAccount(&vcs, currentState, stateInfo.IndexVec, stateInfo.DeltaVec, int(i+1))

		// Generate and store commitment for this state
		vcs.OpenAll(currentState)
		commitment := vcs.Commit(currentState, uint64(stateVecLevel))
		stateInfo.Commitment = commitment

		txnData[i + 1] = stateInfo
		
		// Print transaction data for this round
		fmt.Printf("\n=== Transaction Data for Round %d ===\n", i+1)
		
		// Group transactions by account
		accountTransactions := make(map[uint64][]int)
		for j, idx := range stateInfo.IndexVec {
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
				currentAddress = latestSnapshot.ExtractField(accountIndex, utils.ADDR_OFFSET)
				currentNonce = latestSnapshot.ExtractField(accountIndex, utils.NONCE_OFFSET)
				currentValue = latestSnapshot.ExtractField(accountIndex, utils.VAL_OFFSET)
			}
			
			fmt.Printf("\n  Account[%d] - Address: %d, Current Nonce: %d, Current Value: %d\n", 
				accountIndex, currentAddress, currentNonce, currentValue)
			fmt.Printf("  Transactions in Round %d:\n", i+1)
			
			// For each transaction affecting this account
			for _, txIndex := range txList {
				// Parse delta (the change being applied)
				deltaVal, err := strconv.ParseInt(stateInfo.DeltaVec[txIndex].GetString(10), 10, 64)
				if err != nil {
					fmt.Printf("    Transaction #%d: Error parsing delta\n", txIndex)
					continue
				}
				
				// Extract fields from delta
				addressChange := (deltaVal >> utils.ADDR_OFFSET) & ((1 << 21) - 1)
				nonceChange := (deltaVal >> utils.NONCE_OFFSET) & ((1 << 21) - 1)
				valueChange := (deltaVal >> utils.VAL_OFFSET) & ((1 << 21) - 1)
				
				// Parse value (the account state before transaction)
				valueVal, err := strconv.ParseInt(stateInfo.ValueVec[txIndex].GetString(10), 10, 64)
				if err != nil {
					fmt.Printf("    Transaction #%d: Error parsing value\n", txIndex)
					continue
				}
				
				// Extract fields from current state
				beforeAddress := (valueVal >> utils.ADDR_OFFSET) & ((1 << 21) - 1)
				beforeNonce := (valueVal >> utils.NONCE_OFFSET) & ((1 << 21) - 1)
				beforeValue := (valueVal >> utils.VAL_OFFSET) & ((1 << 21) - 1)
				
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
		if (i + 1) % utils.SLICING_INTERVAL == 0 {
			fmt.Printf("\nCreating snapshot for Round %d...\n", i+1)
			
			// Create a new state array for the snapshot
			snapshotState := make([]mcl.Fr, len(currentState))
			copy(snapshotState, currentState)
			
			// Create and save snapshot using the new state array
			vcs.OpenAll(snapshotState)
			snapshot := utils.NewSlice(snapshotState, getProofs(&vcs, *stateVecSize), vcs.Commit(snapshotState, uint64(stateVecLevel)))
			snapshots = append(snapshots, snapshot)
			fmt.Printf("Saved state snapshot (Round %d)\n", i + 1)
			
			// Print snapshot content
			fmt.Printf("\n=== Snapshot State at Round %d ===\n", i + 1)
			
			// If there's a previous snapshot, calculate state changes
			var prevSnapshot *utils.Slice
			if len(snapshots) > 1 {
				prevSnapshot = snapshots[len(snapshots)-2]
			}
			
			for j := uint64(0); j < *stateVecSize; j++ {
				address := snapshot.ExtractField(j, utils.ADDR_OFFSET)
				nonce := snapshot.ExtractField(j, utils.NONCE_OFFSET)
				value := snapshot.ExtractField(j, utils.VAL_OFFSET)
				
				fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d", 
					j, address, nonce, value)
				
				// If there's a previous snapshot, show state changes
				if prevSnapshot != nil {
					prevNonce := prevSnapshot.ExtractField(j, utils.NONCE_OFFSET)
					prevValue := prevSnapshot.ExtractField(j, utils.VAL_OFFSET)
					
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

	fmt.Println("1. Algorithm 1: Basic algorithm to reconstruct the a list of account proof V and commitment C_i of state S_i")
	fmt.Print("2. Algorithm 2: State Proof: Account acc aij and proof πij exists at state Si")
	fmt.Println(vc.SEP)

	var algorithmChoice int
	fmt.Print("Please enter the number of the algorithm to run: ")
	fmt.Scanf("%d", &algorithmChoice)

	switch algorithmChoice {
	case 1:
		algorithm1.StateReconstruct(&vcs, snapshots, txnData, uint8(stateVecLevel))
	case 2:
		algorithm2.RunAlgorithm2(&vcs, snapshots, txnData, uint8(stateVecLevel))
	}
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
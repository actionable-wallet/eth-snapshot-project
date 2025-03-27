package utils

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/alinush/go-mcl"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

// GenerateTransactionVectors generates vectors for transaction simulation.
// This function only generates the vectors without updating any state.
// Returns:
// - indexVec: List of indices that changed
// - proofVec: Proofs of the changed indices
// - deltaVec: Magnitude of the changes
// - valueVec: Current value in that position
func GenerateTransactionVectors(vcs *vc.VCS, aFr []mcl.Fr, transactionNum uint64, stateVecSize uint64) ([]uint64, [][]mcl.G1, []mcl.Fr, []mcl.Fr) {
	// Initialize random seed
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Generate transactions
	indexVec := make([]uint64, transactionNum)   // List of indices that changed
	proofVec := make([][]mcl.G1, transactionNum) // Proofs of the changed indices
	deltaVec := make([]mcl.Fr, transactionNum)   // Magnitude of the changes
	valueVec := make([]mcl.Fr, transactionNum)   // Current value in that position

	// Generate transaction vectors
	for i := uint64(0); i < transactionNum; i++ {
		// Select random account
		accountIndex := uint64(r.Intn(int(stateVecSize)))
		indexVec[i] = accountIndex
		
		// Get proof for this account
		proofVec[i] = vcs.GetProofPath(accountIndex)
		
		// Generate random value change
		valDelta := r.Intn(1000)

		// Pack the changes into deltaVec
		addressChange := int64(0) << int64(ADDR_OFFSET)
		incrementNonce := int64(1) << int64(NONCE_OFFSET)
		valueChange := int64(valDelta) << int64(VAL_OFFSET)
		delta := addressChange ^ incrementNonce ^ valueChange ^ int64(PAD_OFFSET)
		deltaVec[i].SetInt64(delta)

		// Store current value
		valueVec[i] = aFr[accountIndex]
	}

	return indexVec, proofVec, deltaVec, valueVec
}

// UpdateAccount applies the transaction vectors to update the system state
func UpdateAccount(vcs *vc.VCS, aFr []mcl.Fr, indexVec []uint64, deltaVec []mcl.Fr, stateIndex int) {
	transactionNum := uint64(len(indexVec))
	
	// Store transaction history for each account
	transactionHistory := make(map[uint64][]TransactionRecord)

	// Record transactions
	for i := uint64(0); i < transactionNum; i++ {
		accountIndex := indexVec[i]
		
		// Extract value change from delta
		delta, _ := strconv.ParseInt(deltaVec[i].GetString(10), 10, 64)
		valDelta := (delta >> int64(VAL_OFFSET)) & ((1 << 21) - 1)
		
		// Create transaction record
		tx := TransactionRecord{
			StateIndex: stateIndex,
			AccountIndex: accountIndex,
			ValueDelta:   int(valDelta),
			Nonce:        1,
		}
		
		// Record transaction in history
		transactionHistory[accountIndex] = append(
			transactionHistory[accountIndex], 
			tx,
		)
	}

	// Update the state
	// for i := uint64(0); i < transactionNum; i++ {
	// 	vcs.UpdateProofTree(indexVec[i], deltaVec[i])
	// }

	// Update values
	for i := uint64(0); i < transactionNum; i++ {
		mcl.FrAdd(&aFr[indexVec[i]], &aFr[indexVec[i]], &deltaVec[i])
	}

	// Display transaction history
	fmt.Printf("\n=== Transaction History (State %d) ===\n", stateIndex - 1)
	for account, txs := range transactionHistory {
		fmt.Printf("\nAccount %d transaction history:\n", account)
		for _, tx := range txs {
			fmt.Printf("  State %d: Value Change %d, Nonce %d\n",
				tx.StateIndex - 1, tx.ValueDelta, tx.Nonce)
		}
	}

	// Print final state
	fmt.Println("\n=== Current Account States ===")
	for i := uint64(0); i < uint64(len(aFr)); i++ {
		val, _ := strconv.ParseInt(aFr[i].GetString(10), 10, 64)
		address := (val >> int64(ADDR_OFFSET)) & ((1 << 21) - 1)
		nonce := (val >> int64(NONCE_OFFSET)) & ((1 << 21) - 1)
		value := (val >> int64(VAL_OFFSET)) & ((1 << 21) - 1)
		fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n",
			i, address, nonce, value)
	}
}

// This function returns the IndexVec and DeltaVec for the given range of states
func GetTransactionList(beginIndex uint64, endIndex uint64, txnData []StateInfo) ([]uint64, []mcl.Fr, []mcl.Fr) {
	fmt.Printf("Getting transactions from state %d to state %d\n", beginIndex, endIndex)
	
	// Collect all transactions
	var allIndexVec []uint64
	var allDeltaVec []mcl.Fr
	var allValueVec []mcl.Fr
	
	// Map to track the latest state for each account
	valueMap := make(map[uint64]mcl.Fr)
	updateMap := make(map[uint64]mcl.Fr)
	
	// Process each state in order
	for i := beginIndex; i <= endIndex; i++ {
		state := txnData[i]
		fmt.Printf("Processing state %d with %d transactions\n", i, len(state.IndexVec))
		
		// Process each transaction
		for j := 0; j < len(state.IndexVec); j++ {
			accountIndex := state.IndexVec[j]
			delta := state.DeltaVec[j]
			value := state.ValueVec[j]
			
			// If this is the first transaction for this account, record its initial value
			if _, exists := valueMap[accountIndex]; !exists {
				valueMap[accountIndex] = value
			}
			
			// Accumulate delta
			temp := updateMap[accountIndex]
			mcl.FrAdd(&temp, &temp, &delta)
			updateMap[accountIndex] = temp
			
			allIndexVec = append(allIndexVec, accountIndex)
			allDeltaVec = append(allDeltaVec, delta)
		}
	}
	
	// Apply all updates to valueMap
	for key, delta := range updateMap {
		temp := valueMap[key]
		mcl.FrAdd(&temp, &temp, &delta)
		valueMap[key] = temp
	}
	
	// Build the final valueVec
	allValueVec = make([]mcl.Fr, len(allIndexVec))
	for i, index := range allIndexVec {
		allValueVec[i] = valueMap[index]
	}
	
	fmt.Printf("Total transactions: %d\n", len(allIndexVec))
	fmt.Printf("Unique accounts: %d\n", len(valueMap))
	
	return allIndexVec, allDeltaVec, allValueVec
}
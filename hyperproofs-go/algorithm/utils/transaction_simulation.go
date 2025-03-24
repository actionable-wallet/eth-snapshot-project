package utils

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/alinush/go-mcl"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

// Transaction field offsets for bit manipulation
const (
	addressOffset    int64 = 43 	// 21 bits for address
	nonceFieldOffset int64 = 22 	// 21 bits for nonce
	valueOffset     int64 = 1   	// 21 bits for value
	paddingBits     int64 = 0x0 	// 1 bit for padding
)

// TransactionRecord represents a single transaction in the system
type TransactionRecord struct {
	StateIndex        int    	// The round number when this transaction occurred
	AccountIndex uint64 	// The account that this transaction belongs to
	ValueDelta   int    	// The change in value (can be positive or negative)
	Nonce        int64  	// Transaction sequence number for the account
}

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
		addressChange := int64(0) << addressOffset
		incrementNonce := int64(1) << nonceFieldOffset
		valueChange := int64(valDelta) << valueOffset
		delta := addressChange | incrementNonce | valueChange | paddingBits
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
		valDelta := (delta >> valueOffset) & ((1 << 21) - 1)
		
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
		address := (val >> addressOffset) & ((1 << 21) - 1)
		nonce := (val >> nonceFieldOffset) & ((1 << 21) - 1)
		value := (val >> valueOffset) & ((1 << 21) - 1)
		fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n",
			i, address, nonce, value)
	}
} 
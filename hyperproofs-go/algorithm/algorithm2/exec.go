package algorithm2

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/algorithm/utils"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

// RunAlgorithm2 implements the State Proof algorithm
func RunAlgorithm2(vcs *vc.VCS, slices []*utils.Slice, txnData []utils.StateInfo, stateVecLevel uint8) {
	fmt.Println(vc.SEP)
	fmt.Print("Start of Algorithm 2")
	fmt.Println(vc.SEP)

	fmt.Print("Enter state index to prove (0-based): ")
	var targetState uint64
	fmt.Scanf("%d", &targetState)

	fmt.Print("Enter account index to prove (0-based): ")
	var accountIndex uint64
	fmt.Scanf("%d", &accountIndex)

	// 1. Prover section
	result := StateProof(vcs, slices, txnData, targetState, accountIndex)

	// 2. Verifier section
	VerifyStateProof(vcs, result, txnData[targetState].Commitment)

	fmt.Println(vc.SEP)
	fmt.Print("End of Algorithm 2")
	fmt.Println(vc.SEP)
}

// StateProof implements the Prover section
func StateProof(vcs *vc.VCS, slices []*utils.Slice, txnData []utils.StateInfo, targetState uint64, accountIndex uint64) *utils.StateProofResult {
	// 1. Find the closest slice
	closestSlice, sliceIndex := utils.FindCLoestSlice(vcs, slices, targetState)
	fmt.Printf("\nRecovering state %d from the slice at state %d...\n", targetState, sliceIndex)

	// 2. Get transaction list
	fmt.Printf("Getting transaction data from state %d to state %d...\n", sliceIndex, targetState)
	indexVec, deltaVec, _ := utils.GetTransactionList(sliceIndex+1, targetState, txnData)

	// 3. Update state
	recoveredState := make([]mcl.Fr, len(closestSlice.State))
	copy(recoveredState, closestSlice.State)

	if len(indexVec) > 0 {
		utils.UpdateAccount(vcs, recoveredState, indexVec, deltaVec, int(targetState+1))
	}

	// 4. Get account information and proof
	// 4.1 Get account information
	accountInfo := recoveredState[accountIndex]
	
	// 4.2 Get account delta
	var accountDelta mcl.Fr
	for i, idx := range indexVec {
		if idx == accountIndex {
			// Accumulate all deltas for this account
			mcl.FrAdd(&accountDelta, &accountDelta, &deltaVec[i])
		}
	}

	// 4.3 Get base proof
	baseProof := closestSlice.Proofs[accountIndex]

	// 4.4 Update proof

	// 5. Return result
	// return &utils.StateProofResult{
	// 	State:     recoveredState,
	// 	Accounts:  []mcl.Fr{accountInfo},
	// 	Proof:     updatedProof,
	// 	Delta:     []mcl.Fr{accountDelta},
	// 	BaseProof: baseProof,
	// }
}

// VerifyStateProof implements the Verifier section
func VerifyStateProof(vcs *vc.VCS, result *utils.StateProofResult, commitment mcl.G1) {
	fmt.Println("\n=== Verifying State Proof ===")
	
	// 1. Verify account information and proof
	status, _ := vcs.VerifyMemoized(commitment, []uint64{0}, result.Accounts, [][]mcl.G1{result.Proof})
	
	if status {
		fmt.Println("\033[32mState Proof Verification: SUCCESS ✅\033[0m")
	} else {
		fmt.Println("\033[31mState Proof Verification: FAILED ❌\033[0m")
	}

	// 2. Print account information
	fmt.Printf("\nAccount Information:\n")
	fmt.Println(strings.Repeat("-", 80))
	val, _ := strconv.ParseInt(result.Accounts[0].GetString(10), 10, 64)
	addr := (val >> utils.ADDR_OFFSET) & ((1 << 21) - 1)
	nonce := (val >> utils.NONCE_OFFSET) & ((1 << 21) - 1)
	value := (val >> utils.VAL_OFFSET) & ((1 << 21) - 1)
	fmt.Printf("Address=%d, Nonce=%d, Value=%d\n", addr, nonce, value)
	fmt.Println(strings.Repeat("-", 80))
}

// Prover
// Verifier

package algorithm1

import (
	"fmt"
	"strings"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/algorithm/utils"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

func StateReconstruct(vcs *vc.VCS, slices []*utils.Slice, txnData []utils.StateInfo, stateVecLevel uint8) {
	// start of prover
	fmt.Println(vc.SEP)
	fmt.Print("Start of Algorithm 1")
	fmt.Println(vc.SEP)

	fmt.Println("\n=== State Recovery Test ===")
	fmt.Print("Enter state index to reconstruct (0-based): ")
	var targetState uint64
	fmt.Scanf("%d", &targetState)

	closestSlice, sliceIndex := utils.FindCLoestSlice(vcs, slices, targetState)

	// Get transaction data from the cloest slice to the target state
	fmt.Printf("\nGetting transaction data from state %d to state %d...\n", sliceIndex, targetState)
		
	for i := sliceIndex + 1; i <= targetState; i++ {
		fmt.Println("apply transaction from state", i) 
		transactionList := txnData[i]
		utils.UpdateAccount(vcs, closestSlice.State, transactionList.IndexVec, transactionList.DeltaVec, int(i+1))
	}

	// // Generate commitment for the recovered state
	// vcs.OpenAll(closestSlice.State)
	// recoveredCommitment := vcs.Commit(closestSlice.State, uint64(stateVecLevel))
	indexVec, deltaVec, valueVec := utils.GetTransactionList(sliceIndex + 1, targetState, txnData)
	
	var targetCommitment mcl.G1
	// If there are no transactions to apply, use the current state commitment
	if len(indexVec) == 0 {
		targetCommitment = txnData[sliceIndex].Commitment
	} else {
		proofVec := make([][]mcl.G1, len(indexVec))
		for k := uint64(0); k < uint64(len(indexVec)); k++ {
			proofVec[k] = vcs.GetProofPath(indexVec[k])
		}

		for i := uint64(0); i < uint64(len(txnData)); i++ {
			fmt.Println("State", i, "Commitment", txnData[i].Commitment)
		}
		fmt.Println("IndexVec", indexVec)
		fmt.Println("DeltaVec", deltaVec)
		fmt.Println("ValueVec", valueVec)
		fmt.Println("SliceIndex", sliceIndex)
		targetCommitment = vcs.UpdateComVec(txnData[sliceIndex].Commitment, indexVec, deltaVec)
		fmt.Println("TargetCommitment", targetCommitment)

		status, _ := vcs.VerifyMemoized(targetCommitment, indexVec, valueVec, proofVec)
		if status {
			fmt.Println("\033[32mUpdateProofTree Passed ✅\033[0m")
		} else {
			fmt.Println("\033[31mUpdateProofTree Failed ❌\033[0m")
		}
	}
	// End of prover
	
	// Start of verifier
	// Compare with original commitment
	originalCommitment := txnData[targetState].Commitment
	
	if targetCommitment.IsEqual(&originalCommitment) {
		fmt.Println("\033[32mCommitment verification: SUCCESS - Recovered state matches original state ✅\033[0m")
	} else {
		fmt.Println("\033[31mCommitment verification: FAILED - Recovered state differs from original state ❌\033[0m")
	}

	// Print the recovered state
	fmt.Printf("\nRecovered State at Round %d:\n", targetState)
	fmt.Println(strings.Repeat("-", 80))
	for i := uint64(0); i < vcs.N; i++ {
		addr := closestSlice.ExtractField(i, utils.ADDR_OFFSET)
		nonce := closestSlice.ExtractField(i, utils.NONCE_OFFSET)
		value := closestSlice.ExtractField(i, utils.VAL_OFFSET)
		
		fmt.Printf("Account[%d]: Address=%d, Nonce=%d, Value=%d\n", 
			i, addr, nonce, value)
	}
	fmt.Println(strings.Repeat("-", 80))

	fmt.Println(vc.SEP)
	fmt.Print("End of Algorithm 1")
	fmt.Println(vc.SEP)
	// End of verifier
}
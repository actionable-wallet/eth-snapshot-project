package algorithm2

import (
	"fmt"

	"github.com/hyperproofs/hyperproofs-go/algorithm/utils"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

func RunAlgorithm2(vcs *vc.VCS, snapshots []*utils.Slice, txnData []utils.StateInfo, stateVecLevel uint8) {
	fmt.Println(vc.SEP)
	fmt.Print("Start of Algorithm 2")
	fmt.Println(vc.SEP)

	fmt.Print("Enter round number to recover (0-based): ")
	var targetRound uint64
	fmt.Scanf("%d", &targetRound)

	fmt.Println(vc.SEP)
	fmt.Print("End of Algorithm 2")
	fmt.Println(vc.SEP)
}

func RunProver(vcs *vc.VCS, snapshots []*utils.Slice, txnData []utils.StateInfo, stateVecLevel uint8, targetRound uint64) {
	recoveredSlice, snapshotRound := utils.FindCLoestSlice(vcs, snapshots, targetRound)

	// Apply transactions from the snapshot round to the target round
	fmt.Printf("\nApplying transactions from round %d to %d...\n", snapshotRound, targetRound)
		
	if snapshotRound != targetRound {
		for i := snapshotRound + 1; i <= targetRound; i++ {
			fmt.Println("apply transaction from round", i)
			roundInfo := txnData[i]
			utils.UpdateAccount(vcs, recoveredSlice.State, roundInfo.IndexVec, roundInfo.DeltaVec, int(i+1))
		}
	}
}

func RunVerifier() {

}

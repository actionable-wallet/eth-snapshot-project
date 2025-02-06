package main
/*
1. Store commitments, lets say in an array of VCs
2. Store transactions in a key-value mapping (reference Joseph's text)
3. How do they do homomorphism


*/
import (
	"flag"
	"fmt"
	"os"
	"testing"
	"time"
	"strconv"
	"math/rand"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/vcs"
)

const FOLDER = "./pkvk-26"

var transactionData = make(map[int][]int)

const addrOffset int = 43
const nonceOffset int = 22
const valOffset int = 1
const padding int = 0x0

func main() {
	testing.Init()
	flag.Parse()
	fmt.Println("Hello, World!")
	mcl.InitFromString("bls12-381")

	dt := time.Now()
	fmt.Println("Specific date and time is: ", dt.Format(time.UnixDate))

	fmt.Println(vcs.SEP)

	args := os.Args

	if len(args) == 1 {
		var L uint8
		L = uint8(2)
		// _ = hyperGenerateKeys(L, false)
		slicingVCS(L, 20)
		// BenchmarkVCSCommit(L, 20)
		fmt.Println("Finished")
	} 
}

func incrementNonce(delta mcl.Fr) {
// 	var deltaNonce = 1 << nonceOffset
// 	return delta.SetInt64(deltaNonce)
// }
}

func getAdditiveInverse() {

}

func extractValue(aFr []mcl.Fr, index uint64) {
	var mask int64 = ((1 << 21) - 1) << valOffset   // Explicitly declaring uint64 type

    //fmt.Printf("Binary:%064b\n", mask)  // Output: 111111111111111111111
	val, err := strconv.ParseInt(aFr[index].GetString(10), 10, 64) // Convert string to int
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Val:", (val & mask) >> valOffset)
}

func extractNonce(aFr []mcl.Fr, index uint64) {
	var mask int64 = ((1 << 21) - 1) << nonceOffset   // Explicitly declaring uint64 type

    fmt.Printf("Binary:%064b\n", mask)  // Output: 111111111111111111111
	val, err := strconv.ParseInt(aFr[index].GetString(10), 10, 64) // Convert string to int
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	//fmt.Println("Value:")
	//fmt.Printf("Binary:%064b\n", val) 
	fmt.Println("After:")
	//fmt.Printf("Binary:%064b\n", (val & mask)) 
	fmt.Println("Nonce:", (val & mask) >> nonceOffset)
}

func slicingVCS(L uint8, txnLimit uint64) {
	N := uint64(1) << L
	K := txnLimit
	vcs := vc.VCS{}
	vcs.KeyGenLoad(16, L, FOLDER, K)

	//var initCommit mcl.G1 = vcs.Commit(aFr, uint64(L))
	// var delta1 mcl.Fr
	// var delta2 mcl.Fr

	//digest = vcs.Commit(aFr, uint64(L))
	
	
	// for i := 0; i < 100; i++ {
	// 	var acc_i = rand.Intn(3)
	// 	var acc_j = rand.Intn(3)
	// 	for acc_i != acc_j {
	// 		acc_j = rand.Intn(3)
	// 	}
	// 	// Ensure a non-zero value
	// 	var transAcc = rand.Intn(50) + 1
	// 	var delta1 mcl.Fr 
	// 	var delta2 mcl.Fr
	
	// 	delta1 = increment(delta1)
	// 	delta2 = incrementNonce(delta2)
	
	// 	deltaNonce = 1 << nonceOffset
	// 	delta1Val = transAcc << 
	// 	transAcc << valOffset
	// }
	indexVec := make([]uint64, K)   // List of indices that chanaged (there can be duplicates.)
	proofVec := make([][]mcl.G1, K) // Proofs of the changed indices.
	deltaVec := make([]mcl.Fr, K)   // Magnitude of the changes.
	valueVec := make([]mcl.Fr, K)   // Current value in that position.

	var digest mcl.G1
	var status bool
	{
		aFr := vc.GenerateVector(N)
		extractValue(aFr, 0)
		extractNonce(aFr, 0)
		digest = vcs.Commit(aFr, uint64(L))
		vcs.OpenAll(aFr)
		
		addressChange := 0x0 << addrOffset
		incrementNonce := 0x1 << nonceOffset
		for k := uint64(0); k < K; k++ {
			indexVec[k] = uint64(rand.Intn(int(N)))
			proofVec[k] = vcs.GetProofPath(indexVec[k])
			valDelta := rand.Intn(1000) << valOffset
			delta := int64(addressChange ^ incrementNonce ^ valDelta ^ padding)
			// 0 in 21 MSB bits, 0x1 in next 21 bits (increment nonce) // random 21bit value
			deltaVec[k].SetInt64(delta)
			valueVec[k] = aFr[indexVec[k]]
			transactionData[int(indexVec[k])] = append(transactionData[int(indexVec[k])], valDelta)
			// Need to map to inverse in order to show negative
		}
	}
	fmt.Println("Before")
	for i := uint64(0); i < 3; i++ {
		fmt.Println(valueVec[i])
		extractValue(valueVec, i)
	}

	status = true
	var loc uint64

	for k := uint64(0); k < K; k++ {
		loc = indexVec[k]
		// status = status && vcs.Verify(digest, loc, valueMap[loc], proofVec[k])
		status = status && vcs.Verify(digest, loc, valueVec[k], proofVec[k])
		if status == false {
			fmt.Println("Error!")
		} else {
			fmt.Println("\033[32mVerification Passed ✅\033[0m")
		}
	}
	

	status = true
	status, _ = vcs.VerifyMemoized(digest, indexVec, valueVec, proofVec)
	if status == false {
		fmt.Println("Fast Verification Failed")
	} else {
		fmt.Println("\033[32mFast Verification Passed ✅\033[0m")
	}
	

	// Make some changes to the vector positions.
	for k := uint64(0); k < K; k++ {
		loc := indexVec[k]
		delta := deltaVec[k]
		vcs.UpdateProofTree(loc, delta)
	}

	// Update the value vector
	valueVec = SecondaryStateUpdate(indexVec, deltaVec, valueVec)

	// Get latest proofs
	for k := uint64(0); k < K; k++ {
		proofVec[k] = vcs.GetProofPath(indexVec[k])
	}

	digest = vcs.UpdateComVec(digest, indexVec, deltaVec)

	status = true
	status, _ = vcs.VerifyMemoized(digest, indexVec, valueVec, proofVec)
	if status == false {
		fmt.Println("UpdateProofTree Failed")
	} else {
		fmt.Println("\033[32mUpdateProofTree Passed ✅\033[0m")
	}


	vcs.UpdateProofTreeBulk(indexVec, deltaVec)

	// Update the value vector
	valueVec = SecondaryStateUpdate(indexVec, deltaVec, valueVec)

	// Get latest proofs
	for k := uint64(0); k < K; k++ {
		proofVec[k] = vcs.GetProofPath(indexVec[k])
	}
	digest = vcs.UpdateComVec(digest, indexVec, deltaVec)

	
	status = true
	status, _ = vcs.VerifyMemoized(digest, indexVec, valueVec, proofVec)
	if status == false {
		fmt.Println("UpdateProofTreeBulk Failed")
	} else {
		fmt.Println("\033[32mUpdateProofTreeBulk Passed ✅\033[0m")
	}
	fmt.Println(vc.SEP)
	fmt.Println("Transaction Data:")
	fmt.Println(transactionData)
	fmt.Println(vc.SEP)
	// var aggProof batch.Proof
	// aggProof = vcs.AggProve(indexVec, proofVec)

	

	// status = status && vcs.AggVerify(aggProof, digest, indexVec, valueVec)
	// if status == false {
	// 	fmt.Println("Aggregation failed")
	// }


	// // Simple do another round of updates to check if aggregated succeeded
	// vcs.UpdateProofTreeBulk(indexVec, deltaVec)
	// valueVec = SecondaryStateUpdate(indexVec, deltaVec, valueVec)
	// for k := uint64(0); k < K; k++ {
	// 	proofVec[k] = vcs.GetProofPath(indexVec[k])
	// }
	// digest = vcs.UpdateComVec(digest, indexVec, deltaVec)

	// var aggIndex []uint64
	// var aggProofIndv [][]mcl.G1
	// var aggValue []mcl.Fr

	// aggIndex = make([]uint64, txnLimit)
	// aggProofIndv = make([][]mcl.G1, txnLimit)
	// aggValue = make([]mcl.Fr, txnLimit)

	// for j := uint64(0); j < txnLimit; j++ {
	// 	id := uint64(rand.Intn(int(K))) // Pick an index from the saved list of vector positions
	// 	aggIndex[j] = indexVec[id]
	// 	aggProofIndv[j] = proofVec[id]
	// 	aggValue[j] = valueVec[id]
	// }

	// aggProof = vcs.AggProve(aggIndex, aggProofIndv)
	

	// status = status && vcs.AggVerify(aggProof, digest, aggIndex, aggValue)
	// if status == false {
	// 	fmt.Println("Aggregation#2 failed")
	// }
	fmt.Println("After")
	for i := uint64(0); i < 3; i++ {
		fmt.Println(valueVec[i])
		extractValue(valueVec, i)
	}


}

func SecondaryStateUpdate(indexVec []uint64, deltaVec []mcl.Fr, valueVec []mcl.Fr) []mcl.Fr {

	K := uint64(len(indexVec))
	valueMap := make(map[uint64]mcl.Fr)  // loc: Current value in that position.
	updateMap := make(map[uint64]mcl.Fr) // loc: Magnitude of the changes.

	for k := uint64(0); k < K; k++ {
		valueMap[indexVec[k]] = valueVec[k]
	}

	// Make some changes to the vector positions.
	for k := uint64(0); k < K; k++ {
		loc := indexVec[k]
		delta := deltaVec[k]
		temp := updateMap[loc]
		mcl.FrAdd(&temp, &temp, &delta)
		updateMap[loc] = temp
	}

	// Import the bunch of changes made to local slice of aFr
	for key, value := range updateMap {
		temp := valueMap[key]
		mcl.FrAdd(&temp, &temp, &value)
		valueMap[key] = temp
	}

	// Update the value vector
	for k := uint64(0); k < K; k++ {
		valueVec[k] = valueMap[indexVec[k]]
	}

	return valueVec
}

func BenchmarkVCSCommit(L uint8, txnLimit uint64) string {
	N := uint64(1) << L
	K := txnLimit
	vcs := vc.VCS{}
	vcs.KeyGenLoad(16, L, FOLDER, K)

	aFr := vc.GenerateVector(N)
	vc.SaveVector(N, aFr)
	dt := time.Now()
	vcs.Commit(aFr, uint64(L))
	
	fmt.Println(vc.SEP)
	duration := time.Since(dt)
	out := fmt.Sprintf("BenchmarkVCS/%d/Commit;%d%40d ns/op", L, txnLimit, duration.Nanoseconds())
	fmt.Println(vc.SEP)
	fmt.Println(out)
	fmt.Println(vc.SEP)

	for i, v := range aFr {
		fmt.Printf("aFr[%d] = %s\n", i, v.GetString(10))
	}
	

	
	return out
}


func hyperGenerateKeys(L uint8, fake bool) *vcs.VCS {

	N := uint64(1) << L
	vcs := vcs.VCS{}

	fmt.Println("L:", L, "N:", N)
	folderPath := fmt.Sprintf("pkvk-%02d", L)
	/*
	Altered key generation parameters from 2^12 => 2^7
	Do not need to alter it. 
	*/
	vcs.KeyGen(16, L, folderPath, 128)

	fmt.Println("KeyGen ... Done")
	return &vcs
}

func hyperLoadKeys(L uint8) *vcs.VCS {

	folderPath := fmt.Sprintf("pkvk-%02d", L)
	vcs := vcs.VCS{}

	vcs.KeyGenLoad(16, L, folderPath, 128)

	fmt.Println("KeyGenLoad ... Done")
	return &vcs
}

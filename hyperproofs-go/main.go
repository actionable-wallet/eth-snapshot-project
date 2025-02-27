package main

/*
1. Store commitments, lets say in an array of VCs
2. Store transactions in a key-value mapping (reference Joseph's text)
3. How do they do homomorphism


*/
import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/vcs"
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
)

const FOLDER = "./pkvk-02"

var transactionData = make(map[int][]int)

const addrOffset int = 43
const nonceOffset int = 22
const valOffset int = 1
const padding int = 0x0

func main() {
	testing.Init()
	flag.Parse()
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

func extractValue(aFr []mcl.Fr, index uint64) {
	var mask int64 = ((1 << 21) - 1) << valOffset // Explicitly declaring uint64 type

	//fmt.Printf("Binary:%064b\n", mask)  // Output: 111111111111111111111
	val, err := strconv.ParseInt(aFr[index].GetString(10), 10, 64) // Convert string to int
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Val:", (val&mask)>>valOffset)
}

func extractNonce(aFr []mcl.Fr, index uint64) {
	var mask int64 = ((1 << 21) - 1) << nonceOffset // Explicitly declaring uint64 type

	fmt.Printf("Binary:%064b\n", mask)                             // Output: 111111111111111111111
	val, err := strconv.ParseInt(aFr[index].GetString(10), 10, 64) // Convert string to int
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	//fmt.Println("Value:")
	//fmt.Printf("Binary:%064b\n", val)
	fmt.Println("After:")
	//fmt.Printf("Binary:%064b\n", (val & mask))
	fmt.Println("Nonce:", (val&mask)>>nonceOffset)
}

// Hyperproofs - Sizes(asymptoics and kB) and Proof generation (asymptotics and timings)
// Experiments of verifying costs
func slicingVCS(L uint8, txnLimit uint64) {
	for i := 0; i < 3; i++ {
		fmt.Println("Iteration:", i)
		N := uint64(1) << L
		K := txnLimit

		vcs := vc.VCS{}
		vcs.KeyGenLoad(16, L, FOLDER, K)
		indexVec := make([]uint64, K)   // List of indices that c
		proofVec := make([][]mcl.G1, K) // Proofs of the changed indices.
		deltaVec := make([]mcl.Fr, K)   // Magnitude of the changes.
		valueVec := make([]mcl.Fr, K)   // Current value in that position.
		// TODO: Store intermeditary proof trees
		// Account for lambda constant
		// Sizes (asymptotic and kB)
		// Proof generation
		var digest mcl.G1
		var status bool

		aFr := vc.GenerateVector(N)
		vc.SaveVector(N, aFr)

		extractValue(aFr, 0)
		extractNonce(aFr, 0)
		digest = vcs.Commit(aFr, uint64(L))
		vcs.OpenAll(aFr)

		addressChange := 0x0 << addrOffset
		incrementNonce := 0x1 << nonceOffset
		// vc analogy of mpt states
		for k := uint64(0); k < K; k++ {
			indexVec[k] = uint64(rand.Intn(int(N)))
			proofVec[k] = vcs.GetProofPath(indexVec[k])
			valDelta := rand.Intn(1000) << valOffset
			delta := int64(addressChange ^ incrementNonce ^ valDelta ^ padding)
			// 0 in 21 MSB bits, 0x1 in next 21 bits (increment nonce) // random 21bit value
			deltaVec[k].SetInt64(delta)
			valueVec[k] = aFr[indexVec[k]]
			valDelta = valDelta >> valOffset

			index := int(indexVec[k])
			for i := 0; i < 4; i++ {
				if i != index {
					transactionData[i] = append(transactionData[i], 0)
				}
			}
			transactionData[index] = append(transactionData[index], valDelta)

			// fmt.Println(vc.SEP)
			// fmt.Println(indexVec)
			// fmt.Println(vc.SEP)
			// fmt.Println(proofVec)
			// fmt.Println(vc.SEP)
			// fmt.Println(deltaVec)
			// fmt.Println(vc.SEP)
			// fmt.Println(valueVec)
			// store data
			// consider only doing this once every lambda
			// if k % lambda == 0:
			vcs.OpenAll(aFr)
			// vcs contains the state information at the kth snapshot(not the slice)
			// Need to map to inverse in order to show negative
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
			// Alter for some constant lambda
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
		for account, transactions := range transactionData {
			fmt.Printf("Account %d: %v\n", account, transactions)
	}
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

// Input: si: the state to be queried, k: the index of the account to be queried
// Output: the value in account k at state si
// Assume snapshots are sorted in lexicographic order which represents the order of the states.
// func RetrieveStateData(si []mcl.Fr, k uint64, snapshots [][]mcl.Fr, indexVec []uint64, deltaVec []mcl.Fr) mcl.Fr {
// 	// Step 1: Finds the state sj
// 	sj := findClosestSnapshot(si, snapshots)

// 	// Step 2: Recovers all transactions between si and sj, generates a snapshot for the intermidiate state
// 	T_delta := recoverTransactions(si, sj, indexVec, deltaVec)

// 	// Step 3: Computes the value of the kth position
// 	var result mcl.Fr
// 	mcl.FrAdd(&result, &sj[k], &T_delta[k])
// 	return result
// }

// // This function uses binary search to find the closest snapshot to the given state.
// func findClosestSnapshot(si []mcl.Fr, snapshots [][]mcl.Fr) []mcl.Fr {
// 	low, high := 0, len(snapshots)-1
// 	closest := snapshots[0]
// 	for low <= high {
// 		mid := low + (high-low)/2
// 		if compareSnapshots(snapshots[mid], si) <= 0 {
// 			closest = snapshots[mid]
// 			low = mid + 1
// 		} else {
// 			high = mid - 1
// 		}
// 	}
// 	return closest
// }

// This function comapres two snapshots according to the lexicographic order.
// func compareSnapshots(a, b []mcl.Fr) int {
// 	n := len(a)
// 	for i := 0; i < n; i++ {
// 		s1 := a[i].GetString(10)
// 		s2 := b[i].GetString(10)
// 		if s1 < s2 {
// 			return -1
// 		} else if s1 > s2 {
// 			return 1
// 		}
// 	}
// 	return 0
// }

// This function recovers all transactions between two states.
// How to check whether a transacton happened between two states?
// func recoverTransactions(si, sj []mcl.Fr, indexVec []uint64, deltaVec []mcl.Fr) []mcl.Fr {
// 	T_delta := make([]mcl.Fr, len(sj))
// 	for i := range T_delta {
// 		T_delta[i].SetInt64(0)
// 	}

// 	for i := 0; i < len(indexVec); i++ {
// 		account := indexVec[i]
// 		mcl.FrAdd(&T_delta[account], &T_delta[account], &deltaVec[i])
// 	}
// 	return T_delta
// }

// Input: si: a state si to be queried of the verifier's choice
// Output: A state proof for the query
// func GetStateProof(vcs vcs.VCS, si []mcl.Fr, snapshots [][]mcl.Fr, indexVec []uint64, deltaVec []mcl.Fr) {
// 	// Step1: Chooses a random position k
// 	k := uint64(rand.Intn(len(si)))

// 	// Step2: Finds the closest snapshot and calculates the delta between two states
// 	sj := findClosestSnapshot(si, snapshots)
// 	T_delta := recoverTransactions(si, sj, indexVec, deltaVec)

// 	// Step3: Computes the proof path for the kth position
// 	si_prime := make([]mcl.Fr, len(si))
// 	for i := range si {
// 		mcl.FrAdd(&si_prime[i], &sj[i], &T_delta[i])
// 	}
// 	digest := vcs.Commit(si_prime, uint64(len(si_prime)))
// 	proofPath := vcs.GetProofPath(k)

// 	// Step4: The verifier verifies the proof
// 	status := vcs.Verify(digest, k, si_prime[k], proofPath)
// 	if status {
// 		fmt.Println("State proof is valid ✅")
// 	} else {
// 		fmt.Println("State proof is invalid ❌")
// 	}
// }

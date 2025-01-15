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
	vc "github.com/hyperproofs/hyperproofs-go/vcs"
	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/vcs"
)

const FOLDER = "./pkvk-26"


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
		_ = hyperGenerateKeys(L, false)
		fmt.Println("#1")
		BenchmarkVCSCommit(L, 20)
		fmt.Println("Finished")
	} 
}

func BenchmarkVCSCommit(L uint8, txnLimit uint64) string {
	N := uint64(1) << L
	K := txnLimit
	vcs := vc.VCS{}
	fmt.Println("#3")
	vcs.KeyGenLoad(16, L, FOLDER, K)
	fmt.Println("#4")

	aFr := vc.GenerateVector(N)
	dt := time.Now()
	vcs.Commit(aFr, uint64(L))
	duration := time.Since(dt)
	out := fmt.Sprintf("BenchmarkVCS/%d/Commit;%d%40d ns/op", L, txnLimit, duration.Nanoseconds())
	fmt.Println(vc.SEP)
	fmt.Println(out)
	fmt.Println(vc.SEP)
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

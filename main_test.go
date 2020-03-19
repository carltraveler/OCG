package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/merkle"
)

func TestVerifySubTreeLeaf(t *testing.T) {
	// need load TreeSize first. if tree already exist.
	defer clean()
	clean()

	os.RemoveAll(levelDBName)
	os.RemoveAll(fileHashStoreName)
	os.RemoveAll("Log")

	err := InitCompactMerkleTree()
	if err != nil {
		t.Fatalf("%s", err)
		return
	}
	maxBatchNum = uint32(256)
	offChainMode = true
	DefConfig = ServerConfig{
		Walletname:      "./wallet.dat",
		Walletpassword:  "123456",
		OntNode:         "http://localhost:20336",
		SignerAddress:   "APHNPLz2u1JUXyD8rhryLaoQrW46J3P6y2",
		ServerPort:      32339,
		Contracthexaddr: "8ce5b4c91f89aa72662d5fa9db5ee642b57dfd05",
	}

	err = InitSigner()
	if err != nil {
		return err
	}
	go handleStoreRequest()

	numbatch := uint32(8500)
	N := uint32(256)
	tree := MerkleInit()
	//var alladdargs []string
	//alladdargs := make([]string, numbatch, numbatch)

	fmt.Printf("prepare args\n")
	for m := uint32(0); m < numbatch; m++ {
		if m%1000 == 0 {
			fmt.Printf("send %d\n", m)
		}
		var leafs []common.Uint256
		//var root []common.Uint256
		leafs = GenerateLeafv(uint32(0)+N*m, N)
		getleafvroot(leafs, tree, false)
		//printLeafs("root", root)
		addArgs := leafvToAddArgs(leafs)
		err := rpcBatchAdd([]interface{}{addArgs})
		if err != nil {
			panic(err)
		}
		if DefMerkleTree.TreeSize() != tree.TreeSize() {
			fmt.Printf("right root %x, treeSize %d\n", tree.Root(), tree.TreeSize())
			fmt.Printf("DefWr root %x, treeSize %d\n", DefMerkleTree.Root(), DefMerkleTree.TreeSize())
		}
	}
	fmt.Printf("prepare args done\n")
	fmt.Printf("right root %x, treeSize %d\n", tree.Root(), tree.TreeSize())
	fmt.Printf("Defro root %x, treeSize %d\n", DefMerkleTree.Root(), DefMerkleTree.TreeSize())

}

func GenerateLeafv(start uint32, N uint32) []common.Uint256 {
	sink := common.NewZeroCopySink(nil)
	leafs := make([]common.Uint256, 0)
	for i := uint32(start); i < start+N; i++ {
		sink.Reset()
		sink.WriteUint32(i)
		leafs = append(leafs, hashLeaf(sink.Bytes()))
	}

	return leafs
}

func MerkleInit() *merkle.CompactMerkleTree {
	//store, _ := merkle.NewFileHashStore("merkletree.db", 0)
	tree := merkle.NewTree(0, nil, nil)
	return tree
}

func getleafvroot(leafs []common.Uint256, tree *merkle.CompactMerkleTree, needroot bool) []common.Uint256 {
	root := make([]common.Uint256, 0)
	for i := range leafs {
		tree.AppendHash(leafs[i])
		if needroot {
			root = append(root, tree.Root())
		}
	}

	return root
}

func leafvToAddArgs(leafs []common.Uint256) string {
	sink := common.NewZeroCopySink(nil)
	for i := range leafs {
		sink.WriteHash(leafs[i])
	}

	return hex.EncodeToString(sink.Bytes())
}

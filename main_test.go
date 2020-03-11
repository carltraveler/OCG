package main

import (
	"os"
	"testing"

	"github.com/ontio/ontology/common"
)

func TestVerifySubTreeLeaf(t *testing.T) {
	// need load TreeSize first. if tree already exist.
	defer clean()
	clean()

	os.RemoveAll(levelDBName)
	os.RemoveAll(fileHashStoreName)

	err := InitCompactMerkleTree()
	if err != nil {
		t.Fatalf("%s", err)
		return
	}

	sink := common.NewZeroCopySink(nil)

	N := uint32(10)
	hashes := make([]common.Uint256, N, N)
	root := make([]common.Uint256, N, N)
	for i := uint32(0); i < N; i++ {
		sink.Reset()
		sink.WriteUint32(i)
		hashes[i] = hashLeaf(sink.Bytes())
		BatchAdd(DefMerkleTree, DefStore, hashes[i:i+1])
		if err != nil {
			t.Fatalf("%s", err)
		}
		root[i] = DefMerkleTree.Root()
	}

	for i := uint32(0); i < N; i++ {
		sink.Reset()
		sink.WriteUint32(i)
		leaf := hashLeaf(sink.Bytes())
		exist, err := Verify(DefMerkleTree, DefStore, leaf, root[i], i+1)
		if !exist {
			t.Fatalf("Element %d verify failed: %s\n", i, err)
		}

		for k := uint32(i); k < N; k++ {
			exist, err = Verify(DefMerkleTree, DefStore, leaf, root[k], k+1)
			if !exist {
				t.Fatalf("Element %d verify failed: %s\n", i, err)
			}
		}
	}
}

package main

import (
	"testing"

	"github.com/ontio/ontology/common"
)

func TestVerifySubTreeLeaf(t *testing.T) {
	// need load TreeSize first. if tree already exist.
	ocgTree, err := NewTree()
	if err != nil {
		t.Fatalf("%s", err)
		return
	}

	sink := common.NewZeroCopySink(nil)

	N := uint32(1000)
	hashes := make([]common.Uint256, N, N)
	root := make([]common.Uint256, N, N)
	for i := uint32(0); i < N; i++ {
		sink.Reset()
		sink.WriteUint32(i)
		hashes[i] = ocgTree.hashLeaf(sink.Bytes())
		ocgTree.BatchAdd(hashes[i : i+1])
		if err != nil {
			t.Fatalf("%s", err)
		}
		root[i] = ocgTree.Tree.Root()
	}

	for i := uint32(0); i < N; i++ {
		sink.Reset()
		sink.WriteUint32(i)
		leaf := ocgTree.hashLeaf(sink.Bytes())
		exist, err := ocgTree.Verify(leaf, root[i], i+1)
		if !exist || err != nil {
			t.Fatalf("Element %d verify failed: %s\n", i, err)
		}
	}
}

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/store/leveldbstore"
	"github.com/ontio/ontology/merkle"
)

type DataPrefix byte

const (
	PREFIX_INDEX DataPrefix = 0x1
	PREFIX_COUNT DataPrefix = 0x2
)

type OCGMerkle struct {
	lStore *leveldbstore.LevelDBStore
	Tree   *merkle.CompactMerkleTree
}

func NewTree() (*OCGMerkle, error) {
	store, err := merkle.NewFileHashStore("merkletree.db", 0)
	if err != nil {
		return nil, err
	}
	compactMerkleTree := merkle.NewTree(0, nil, store)

	lStore, err := leveldbstore.NewLevelDBStore("hashindex.db")
	if err != nil {
		return nil, err
	}
	tree := &OCGMerkle{
		lStore: lStore,
		Tree:   compactMerkleTree,
	}

	//count, err := tree.getHashCount()
	//if err != nil {
	//	// init
	//}
	tree.updateHashCount(0)

	//tree.Tree.TreeSize = count

	return tree, nil
}

func (self *OCGMerkle) putHashIndex(leaf common.Uint256, index uint32) {
	keyHash := common.NewZeroCopySink(nil)
	keyHash.WriteByte(byte(PREFIX_INDEX))
	keyHash.WriteHash(leaf)

	val := common.NewZeroCopySink(nil)
	val.WriteUint32(index)

	self.lStore.Put(keyHash.Bytes(), val.Bytes())
}

func (self *OCGMerkle) getLeafIndex(leaf common.Uint256) (uint32, error) {
	keyHash := common.NewZeroCopySink(nil)
	keyHash.WriteByte(byte(PREFIX_INDEX))
	keyHash.WriteHash(leaf)

	val, err := self.lStore.Get(keyHash.Bytes())
	if err != nil {
		return 0, err
	}

	source := common.NewZeroCopySource(val)
	res, eof := source.NextUint32()

	if eof {
		return 0, io.ErrUnexpectedEOF
	}

	return res, nil
}

func (self *OCGMerkle) updateHashCount(num uint32) {
	keyCount := common.NewZeroCopySink(nil)
	keyCount.WriteByte(byte(PREFIX_COUNT))
	keyCount.WriteHash(merkle.EMPTY_HASH)

	val := common.NewZeroCopySink(nil)
	val.WriteUint32(num)

	self.lStore.Put(keyCount.Bytes(), val.Bytes())
}

func (self *OCGMerkle) getHashCount() (uint32, error) {
	keyCount := common.NewZeroCopySink(nil)
	keyCount.WriteByte(byte(PREFIX_COUNT))
	keyCount.WriteHash(merkle.EMPTY_HASH)

	val, err := self.lStore.Get(keyCount.Bytes())
	if err != nil {
		return 0, err
	}

	source := common.NewZeroCopySource(val)
	res, eof := source.NextUint32()

	if eof {
		return 0, io.ErrUnexpectedEOF
	}

	return res, nil
}

func (self *OCGMerkle) hashLeaf(data []byte) common.Uint256 {
	tmp := append([]byte{0}, data...)
	return sha256.Sum256(tmp)
}

// duplicate handle
// contract failed handle
func (self *OCGMerkle) BatchAdd(leafv []common.Uint256) error {
	currentcount, err := self.getHashCount()
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(len(leafv)); i++ {
		// consider bloom filter to accelerate this
		_, err := self.getLeafIndex(leafv[i])
		// check exist
		if err == nil {
			return errors.New(fmt.Sprintf("BatchAdd Failed. Hash %x already add in", leafv[i]))
		}

		// call contract to onchain. server drop it if contract operation failed
		self.Tree.AppendHash(leafv[i])
		self.putHashIndex(leafv[i], currentcount)
		currentcount += 1
	}

	self.updateHashCount(currentcount)
	return nil
}

func (self *OCGMerkle) GetProof(leaf_hash common.Uint256, treeSize uint32) ([]common.Uint256, error) {
	index, err := self.getLeafIndex(leaf_hash)
	if err != nil {
		return nil, err
	}

	return self.Tree.InclusionProof(index, treeSize)
}

func (self *OCGMerkle) Verify(leaf common.Uint256, root common.Uint256, treeSize uint32) (bool, error) {
	proof, err := self.GetProof(leaf, treeSize)
	if err != nil {
		return false, err
	}
	verify := merkle.NewMerkleVerifier()

	index, err := self.getLeafIndex(leaf)
	if err != nil {
		return false, err
	}
	err = verify.VerifyLeafHashInclusion(leaf, index, proof, root, treeSize)
	if err != nil {
		return false, err
	}

	return true, nil
}

func main() {
	// need load TreeSize first. if tree already exist.
}

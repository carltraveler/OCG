package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	sdk "github.com/ontio/ontology-go-sdk"
	sdkcom "github.com/ontio/ontology-go-sdk/common"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/common/password"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/store/leveldbstore"
	"github.com/ontio/ontology/core/types"
	utils2 "github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/merkle"
	"github.com/ontio/ontology/smartcontract/states"
	"github.com/urfave/cli"
)

type DataPrefix byte

const (
	PREFIX_INDEX                  DataPrefix = 0x1
	PREFIX_MERKLE_TREE            DataPrefix = 0x2
	PREFIX_TX                     DataPrefix = 0x3
	PREFIX_TX_HASH                DataPrefix = 0x4
	PREFIX_ROOT_HEIGHT            DataPrefix = 0x5
	PREFIX_LATEST_FAILED_TX       DataPrefix = 0x6
	PREFIX_CURRENT_BLOCKHEIGHT    DataPrefix = 0x7
	PREFIX_FILEHASH_APPEND_FAILED DataPrefix = 0x8
)

const (
	levelDBName          string = "leveldb"
	fileHashStoreName    string = "filestore.db"
	TxchCap              uint32 = 5000
	fileHashAppendFailed string = "true"
)

var (
	contractAddress          common.Address
	SystemOutOfService       bool = false
	lastFileHashAppendFailed bool = false
)

type ServerConfig struct {
	Walletname        string   `json:"walletname"`
	OntNode           string   `json:"ontnode"`
	SignerAddress     string   `json:"signeraddress"`
	ServerPort        int      `json:"serverport"`
	GasPrice          uint64   `json:"gasprice"`
	CacheTime         uint32   `json:"cachetime"`
	BatchNum          uint32   `json:"batchnum"`
	TryChainInterval  uint32   `json:"trychaininterval"`
	SendTxInterval    uint32   `json:"sendtxinterval"`
	SendTxSize        uint32   `json:"sendtxsize"`
	BatchAddSleepTime uint32   `json:"batchaddsleeptime"`
	ContracthexAddr   string   `json:"contracthexaddr"`
	Authorize         []string `json:"authorize"`
}

const (
	SUCCESS         int64 = 0
	INVALID_PARAM   int64 = 41001
	ADDHASH_FAILED  int64 = 41002
	VERIFY_FAILED   int64 = 41003
	NODE_OUTSERVICE int64 = 41004
	NO_AUTH         int64 = 41005
)

const TxExecFailed uint32 = 1

var ErrMap = map[int64]string{
	SUCCESS:         "SUCCESS",
	INVALID_PARAM:   "INVALID_PARAM",
	ADDHASH_FAILED:  "ADDHASH_FAILED",
	VERIFY_FAILED:   "VERIFY_FAILED",
	NODE_OUTSERVICE: "NODE_OUTSERVICE",
	NO_AUTH:         "NO_AUTH",
}

func checkAuthorizeOfAddress(address common.Address) bool {
	for _, s := range DefConfig.Authorize {
		addr, err := common.AddressFromBase58(s)
		if err != nil {
			log.Errorf("server Authorize address convert err.")
			return false
		}

		if addr == address {
			return true
		}
	}

	return false
}

type TransactionStore struct {
	// sync have mb.
	Txhashes sync.Map
}

func (self *TransactionStore) CheckHashExist(txh common.Uint256) bool {
	if _, ok := self.Txhashes.Load(txh); !ok {
		return false
	}

	return true
}

// use Barrier to publish.
func (self *TransactionStore) PublishDelHashes(DeleteHashes []common.Uint256) {
	for _, txh := range DeleteHashes {
		self.Txhashes.Delete(txh)
	}

}

func (self *TransactionStore) PublishDelHash(txh common.Uint256) {
	self.Txhashes.Delete(txh)
}

func (self *TransactionStore) PublishAddHashes(addHashes []common.Uint256) {
	for _, txh := range addHashes {
		self.Txhashes.Store(txh, true)
	}
}

// this interface only store addHashes to batch. not publish.
func (self *TransactionStore) UpdateSelfToBatch(store *leveldbstore.LevelDBStore, addHashes []common.Uint256) {
	sink := common.NewZeroCopySink(nil)

	TxStore.Txhashes.Range(func(k, v interface{}) bool {
		h, ok := k.(common.Uint256)
		if !ok {
			panic("UpdateTxStoreChange TxStore hash key is not Uint256")
		}

		sink.WriteHash(h)
		return true
	})

	for _, h := range addHashes {
		sink.WriteHash(h)
	}

	if len(sink.Bytes()) != 0 {
		store.BatchPut(GetKeyByHash(PREFIX_TX_HASH, merkle.EMPTY_HASH), sink.Bytes())
	} else {
		store.BatchDelete(GetKeyByHash(PREFIX_TX_HASH, merkle.EMPTY_HASH))
	}
}

func (self *TransactionStore) UnMarshal(raw []byte) {
	source := common.NewZeroCopySource(raw)
	for {
		h, eof := source.NextHash()
		if eof {
			break
		}
		self.Txhashes.Store(h, true)
	}
}

type transferArg struct {
	leafv []common.Uint256
	tx    *types.MutableTransaction
}

var (
	DefStore      *leveldbstore.LevelDBStore
	DefMerkleTree *merkle.CompactMerkleTree
	DefSdk        *sdk.OntologySdk
	DefVerifyTx   *types.MutableTransaction
	MTlock        *sync.RWMutex
	Existlock     *sync.Mutex
	FileHashStore merkle.HashStore
	TxStore       *TransactionStore
	wg            sync.WaitGroup
	DefConfig     ServerConfig
	DefSigner     sdk.Signer
	txch          = make(chan transferArg, TxchCap)
)

func GetKeyByHash(prefix DataPrefix, h common.Uint256) []byte {
	sink := common.NewZeroCopySink(nil)
	sink.WriteByte(byte(prefix))
	sink.WriteHash(h)
	return sink.Bytes()
}

func InitSigner() error {
	wallet, err := DefSdk.OpenWallet(DefConfig.Walletname)
	if err != nil {
		return fmt.Errorf("error in OpenWallet:%s\n", err)
	}

	passwd, err := password.GetAccountPassword()
	if err != nil {
		return fmt.Errorf("input password error %s", err)
	}

	DefSigner, err = wallet.GetAccountByAddress(DefConfig.SignerAddress, passwd)
	if err != nil {
		return fmt.Errorf("error in GetDefaultAccount:%s\n", err)
	}

	return nil
}

func InitCompactMerkleTree() error {
	var err error
	cMTree := &merkle.CompactMerkleTree{}
	DefStore, err = leveldbstore.NewLevelDBStore(levelDBName)
	if err != nil {
		return err
	}

	rawTree, _ := DefStore.Get(GetKeyByHash(PREFIX_MERKLE_TREE, merkle.EMPTY_HASH))
	if rawTree != nil {
		err := cMTree.UnMarshal(rawTree)
		if err != nil {
			return err
		}
	}

	store, err := merkle.NewFileHashStore(fileHashStoreName, cMTree.TreeSize())
	if err != nil {
		return err
	}
	FileHashStore = store

	DefMerkleTree = merkle.NewTree(cMTree.TreeSize(), cMTree.Hashes(), store)
	if DefMerkleTree.TreeSize() == math.MaxUint32 {
		return errors.New("over max hashes. server stop")
	}
	MTlock = new(sync.RWMutex)
	Existlock = new(sync.Mutex)

	contractAddress, err = common.AddressFromHexString(DefConfig.ContracthexAddr)
	if err != nil {
		return err
	}

	TxStore = &TransactionStore{}

	raw, err := DefStore.Get(GetKeyByHash(PREFIX_TX_HASH, merkle.EMPTY_HASH))
	if err == nil {
		TxStore.UnMarshal(raw)
	}

	rawa, err := DefStore.Get(GetKeyByHash(PREFIX_FILEHASH_APPEND_FAILED, merkle.EMPTY_HASH))
	if err == nil && string(rawa) == fileHashAppendFailed {
		lastFileHashAppendFailed = true
	}

	DefSdk = sdk.NewOntologySdk()
	DefSdk.NewRpcClient().SetAddress(DefConfig.OntNode)

	_, err = DefStore.Get(GetKeyByHash(PREFIX_CURRENT_BLOCKHEIGHT, merkle.EMPTY_HASH))
	if err != nil {
		// localHeight not init. first time init.
		callCount := uint32(0)
		for {
			blockHeight, err := DefSdk.GetCurrentBlockHeight()
			if err != nil || blockHeight == 0 {
				log.Warnf("blockHeight: %d, err: %s", blockHeight, err)
				if callCount > 2 {
					return err
				}
				time.Sleep(time.Second * 1)
				callCount++
				continue
			}

			sinkh := common.NewZeroCopySink(nil)
			sinkh.WriteUint32(blockHeight)
			DefStore.Put(GetKeyByHash(PREFIX_CURRENT_BLOCKHEIGHT, merkle.EMPTY_HASH), sinkh.Bytes())
			break
		}
	}

	SendTxChannel = make(chan bool, DefConfig.SendTxSize)
	for i := uint32(0); i < DefConfig.SendTxSize; i++ {
		SendTxChannel <- true
	}

	go cacheLeafs()
	return nil
}

func SaveCompactMerkleTree(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore) {
	rawTree, _ := cMtree.Marshal()
	store.BatchPut(GetKeyByHash(PREFIX_MERKLE_TREE, merkle.EMPTY_HASH), rawTree)
}

func putLatestFailedTx(store *leveldbstore.LevelDBStore, tx *types.MutableTransaction) error {
	sink := common.NewZeroCopySink(nil)
	imtx, err := tx.IntoImmutable()
	if err != nil {
		return err
	}

	imtx.Serialization(sink)
	store.BatchPut(GetKeyByHash(PREFIX_LATEST_FAILED_TX, merkle.EMPTY_HASH), sink.Bytes())
	return nil
}

func getLatestFailedTx(store *leveldbstore.LevelDBStore) (*types.MutableTransaction, error) {
	var imtx types.Transaction
	raw, err := store.Get(GetKeyByHash(PREFIX_LATEST_FAILED_TX, merkle.EMPTY_HASH))
	if err != nil {
		return nil, err
	}

	source := common.NewZeroCopySource(raw)
	imtx.Deserialization(source)
	tx, err := imtx.IntoMutable()
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func delLatestFailedTx(store *leveldbstore.LevelDBStore) {
	store.BatchDelete(GetKeyByHash(PREFIX_LATEST_FAILED_TX, merkle.EMPTY_HASH))
}

func putTransaction(store *leveldbstore.LevelDBStore, tx *types.MutableTransaction) error {
	sink := common.NewZeroCopySink(nil)
	imtx, err := tx.IntoImmutable()
	if err != nil {
		return err
	}

	imtx.Serialization(sink)
	store.BatchPut(GetKeyByHash(PREFIX_TX, tx.Hash()), sink.Bytes())
	return nil
}

func delTransaction(store *leveldbstore.LevelDBStore, txh common.Uint256) {
	store.BatchDelete(GetKeyByHash(PREFIX_TX, txh))
}

func getTransaction(store *leveldbstore.LevelDBStore, txh common.Uint256) (*types.MutableTransaction, error) {
	var imtx types.Transaction
	raw, err := store.Get(GetKeyByHash(PREFIX_TX, txh))
	if err != nil {
		return nil, err
	}

	source := common.NewZeroCopySource(raw)
	imtx.Deserialization(source)
	tx, err := imtx.IntoMutable()
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func getCurrentLocalBlockHeight(store *leveldbstore.LevelDBStore) (uint32, error) {
	val, err := store.Get(GetKeyByHash(PREFIX_CURRENT_BLOCKHEIGHT, merkle.EMPTY_HASH))
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

func putCurrentLocalBlockHeight(store *leveldbstore.LevelDBStore, height uint32) {
	// update the next handled height.
	sinkh := common.NewZeroCopySink(nil)
	sinkh.WriteUint32(height)
	store.BatchPut(GetKeyByHash(PREFIX_CURRENT_BLOCKHEIGHT, merkle.EMPTY_HASH), sinkh.Bytes())
}

func putRootBlockHeight(store *leveldbstore.LevelDBStore, root common.Uint256, height uint32) {
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint32(height)
	store.BatchPut(GetKeyByHash(PREFIX_ROOT_HEIGHT, root), sink.Bytes())
}

func getRootBlockHeight(store *leveldbstore.LevelDBStore, root common.Uint256) (uint32, error) {
	val, err := store.Get(GetKeyByHash(PREFIX_ROOT_HEIGHT, root))
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

func putLeafIndex(store *leveldbstore.LevelDBStore, leaf common.Uint256, index uint32) {
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint32(index)
	store.BatchPut(GetKeyByHash(PREFIX_INDEX, leaf), sink.Bytes())
}

// not this it not BatchDelete
func delLeafIndex(store *leveldbstore.LevelDBStore, leaf common.Uint256) {
	store.Delete(GetKeyByHash(PREFIX_INDEX, leaf))
}

func getLeafIndex(store *leveldbstore.LevelDBStore, leaf common.Uint256) (uint32, error) {
	val, err := store.Get(GetKeyByHash(PREFIX_INDEX, leaf))
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

func hashLeaf(data []byte) common.Uint256 {
	tmp := append([]byte{0}, data...)
	return sha256.Sum256(tmp)
}

func contractVerifyTransaction(ontSdk *sdk.OntologySdk) (*types.MutableTransaction, error) {
	args := make([]interface{}, 1)
	args[0] = "get_root"

	return getTxWithArgs(ontSdk, args)
}

func constructTransation(ontSdk *sdk.OntologySdk, leafv []common.Uint256) (*types.MutableTransaction, error) {
	if uint32(len(leafv)) > DefConfig.BatchNum {
		return nil, fmt.Errorf("too much elemet. most %d.", DefConfig.BatchNum)
	}

	args := make([]interface{}, 2)
	params := make([]interface{}, len(leafv))
	for i := range leafv {
		params[i] = leafv[i]
	}
	args[0] = "batch_add"
	args[1] = params

	return getTxWithArgs(ontSdk, args)
}

func getTxWithArgs(ontSdk *sdk.OntologySdk, args []interface{}) (*types.MutableTransaction, error) {
	tx, err := utils2.NewWasmVMInvokeTransaction(DefConfig.GasPrice, 8000000, contractAddress, args)
	if err != nil {
		return nil, fmt.Errorf("create tx failed: %s", err)
	}
	err = ontSdk.SignToTransaction(tx, DefSigner)
	if err != nil {
		return nil, fmt.Errorf("signer tx failed: %s", err)
	}
	return tx, nil
}

func RoutineOfAddToLocalStorage() {
	for {
		if SystemOutOfService {
			return
		}
		wg.Add(1)
		defer wg.Done()
		var store leveldbstore.LevelDBStore
		store = *DefStore
		store.NewBatch()

		localHeight, err := getCurrentLocalBlockHeight(&store)
		if err != nil {
			log.Errorf("RoutineOfAddToLocalStorage: %s", err)
			SystemOutOfService = true
			return
		}

		blockHeight, err := DefSdk.GetCurrentBlockHeight()
		if err != nil || blockHeight == 0 {
			log.Warnf("RoutineOfAddToLocalStorage blockHeight: %d, err: %s", blockHeight, err)
			time.Sleep(time.Second * time.Duration(DefConfig.TryChainInterval))
			continue
		}

		if localHeight > blockHeight {
			time.Sleep(time.Second * time.Duration(DefConfig.TryChainInterval))
			continue
		}

		log.Debugf("Local Height: %d, CurrentBlockHeight: %d", localHeight, blockHeight)
		blockevents, err := DefSdk.GetSmartContractEventByBlock(localHeight)
		//log.Debugf("RoutineOfAddToLocalStorage blockevents : %v, err: %s", blockevents, err)
		if err != nil {
			// may packet drop.
			time.Sleep(time.Second * time.Duration(DefConfig.TryChainInterval))
			continue
		}

		// note all block should ledger to vocal or not. can not partly. if error happend all tx in oneblock to local ledger will drop.
		addHashes := make([]common.Uint256, 0, 0)
		var handledMerkleTx bool
		handledMerkleTx = false

		// each block has a such data. memhashstore tmpTree
		memhashstore := NewMemHashStore()
		tmpTree := merkle.NewTree(DefMerkleTree.TreeSize(), DefMerkleTree.Hashes(), memhashstore)

		for _, event := range blockevents {
			// in this loop continue will be very carefull. because must coherence with block sequence.
			txh, err := common.Uint256FromHexString(event.TxHash)
			if err != nil {
				log.Warnf("RoutineOfAddToLocalStorage: %s", err)
				SystemOutOfService = true
				return
			}

			if TxStore.CheckHashExist(txh) {
				select {
				case SendTxChannel <- true:
				default:
				}

				handledMerkleTx = true
				// on the oppsite of Add seq. the del publish should be before delTransaction. but not acctually delete from leveldb because this block handle may failed. and need restart to handle if failed. no matter the tx onchain failed or success. this must be delpublish.
				TxStore.PublishDelHash(txh)

				newroot, newtreeSize, txExecFailed, err := GetChainRootTreeSize(event)
				if err != nil {
					// if err indicates events wrong. consider data loose? try localHeight again.
					log.Warnf("RoutineOfAddToLocalStorage: %s", err)
					SystemOutOfService = true
					return
				}

				tx, err := getTransaction(&store, txh)
				if err != nil {
					// if failed can get from chain. check the program
					log.Fatalf("RoutineOfAddToLocalStorage: txhash: %x. get tx error. %s", txh, err)
					SystemOutOfService = true
					return
				}

				if tx.Hash() != txh {
					log.Fatalf("RoutineOfAddToLocalStorage: txhash: %x. not equal . %x", txh, tx.Hash())
					SystemOutOfService = true
					return
				}

				leafv, err := leafvFromTx(tx)
				if err != nil {
					// if failed can get from chain. check the program
					log.Fatalf("RoutineOfAddToLocalStorage: leafvFromTx. %s", err)
					SystemOutOfService = true
					return
				}

				if txExecFailed {
					newtx, err := constructTransation(DefSdk, leafv)
					if err != nil {
						log.Errorf("RoutineOfAddToLocalStorage: constructTransation failed. %s", err)
						SystemOutOfService = true
						return
					}

					err = putTransaction(&store, newtx)
					if err != nil {
						log.Errorf("RoutineOfAddToLocalStorage: putTransaction failed. %s", err)
						SystemOutOfService = true
						return
					}

					// delete old tx. delete from txstore map ok. if failed will Unmarshal from leveldbstore.
					delTransaction(&store, tx.Hash())
					addHashes = append(addHashes, newtx.Hash())
					// continue to handle next tx. or blocks
					continue
				}

				for i := uint32(0); i < uint32(len(leafv)); i++ {
					if tmpTree.TreeSize() == math.MaxUint32 {
						log.Errorf("RoutineOfAddToLocalStorage: Over max the MaxUint32 merkle size.")
						SystemOutOfService = true
						return
					}
					tmpTree.AppendHash(leafv[i])
					putLeafIndex(&store, leafv[i], tmpTree.TreeSize()-1)
				}

				if newroot != tmpTree.Root() || newtreeSize != tmpTree.TreeSize() {
					SystemOutOfService = true
					log.Fatalf("RoutineOfAddToLocalStorage: chainroot: %x, root : %x, chaintreeSize: %d, treeSize: %d", newroot, tmpTree.Root(), newtreeSize, tmpTree.TreeSize())
					return
				}

				putRootBlockHeight(&store, tmpTree.Root(), localHeight)
				delTransaction(&store, tx.Hash())

				log.Infof("root: %x, treeSize: %d", tmpTree.Root(), tmpTree.TreeSize())
			}
		}

		if !handledMerkleTx {
			sinkh := common.NewZeroCopySink(nil)
			sinkh.WriteUint32(localHeight + 1)
			err := store.Put(GetKeyByHash(PREFIX_CURRENT_BLOCKHEIGHT, merkle.EMPTY_HASH), sinkh.Bytes())
			if err != nil {
				log.Errorf("RoutineOfAddToLocalStorage: %s", err)
			}
			continue
		}

		putCurrentLocalBlockHeight(&store, localHeight+1)
		SaveCompactMerkleTree(tmpTree, &store)
		TxStore.UpdateSelfToBatch(&store, addHashes)

		// BatchCommit here to commit oneblock localstorage.
		if !lastFileHashAppendFailed {
			err = store.BatchCommit()
			if err != nil {
				log.Errorf("RoutineOfAddToLocalStorage: ledger BatchCommit err, %s", err)
				SystemOutOfService = true
				return
			}
		}

		// must after commit success.
		TxStore.PublishAddHashes(addHashes)

		// update merkle tree. note new merkle tree has save to leveldb. so restart will see this. here acctually to handle FileHashStore.
		MTlock.Lock()
		t := merkle.NewTree(tmpTree.TreeSize(), tmpTree.Hashes(), FileHashStore)
		err = FileHashStore.Append(memhashstore.Hashes)
		if err != nil {
			// restore Current height. not the next. when restart append again.
			handleFileStoreFailed(err, localHeight)
			return
		}

		err = FileHashStore.Flush()
		if err != nil {
			// restore Current height. not the next. when restart append again.
			handleFileStoreFailed(err, localHeight)
			return
		}
		DefMerkleTree = t
		MTlock.Unlock()

		// clear the lastFileHashAppendFailed. here success
		lastFileHashAppendFailed = false
		// block handle done. publish the DefMerkleTree to Verify.
	}
}

func handleFileStoreFailed(err error, localHeight uint32) {
	var store leveldbstore.LevelDBStore
	store = *DefStore
	store.NewBatch()

	SystemOutOfService = true
	lastFileHashAppendFailed = true
	// this will cause lose FileHashStore data.
	log.Errorf("RoutineOfAddToLocalStorage: FileHashStore Flush err, %s", err)
	store.BatchPut(GetKeyByHash(PREFIX_FILEHASH_APPEND_FAILED, merkle.EMPTY_HASH), []byte(fileHashAppendFailed))

	// should retry this block again if failed.
	sinkh := common.NewZeroCopySink(nil)
	sinkh.WriteUint32(localHeight)
	store.BatchPut(GetKeyByHash(PREFIX_CURRENT_BLOCKHEIGHT, merkle.EMPTY_HASH), sinkh.Bytes())

	err = store.BatchCommit()
	if err != nil {
		log.Errorf("RoutineOfAddToLocalStorage: %s", err)
	}
	return
}

func GetChainRootTreeSize(event *sdkcom.SmartContactEvent) (common.Uint256, uint32, bool, error) {
	if event.State == 0 {
		log.Warnf("GetChainNotifyByTxHash: Check tx failed. may out of ong. charge your address with ong.")
		// to stop all other gorouting. and must handled all other tx. in localHeight block. resend the failed tx again(of coures reconstruct the tx.)
		return merkle.EMPTY_HASH, 0, true, nil
	}

	var newroot common.Uint256
	var treeSize uint32
	var err error
	switch val := event.Notify[0].States.(type) {
	case []interface{}:
		if len(val) != 2 {
			return merkle.EMPTY_HASH, 0, false, fmt.Errorf("GetChainNotifyByTxHash: batchAdd notify len should be 2.")
		}

		newroot, err = common.Uint256FromHexString(val[0].(string))
		if err != nil {
			return merkle.EMPTY_HASH, 0, false, fmt.Errorf("GetChainNotifyByTxHash: %s", err)
		}

		t, err := strconv.Atoi(val[1].(string))
		if err != nil {
			return merkle.EMPTY_HASH, 0, false, fmt.Errorf("GetChainNotifyByTxHash: %s", err)
		}
		treeSize = uint32(t)
	default:
		return merkle.EMPTY_HASH, 0, false, fmt.Errorf("GetChainNotifyByTxHash: batchAdd notify type should be []interface{}.")
	}

	return newroot, treeSize, false, nil
}

type cacheCh struct {
	Leafs []common.Uint256
}

var (
	cacheChannel     = make(chan cacheCh)
	cacheQuitChannel = make(chan bool)
)

func runleafs(leafsCache []common.Uint256, clean bool) []common.Uint256 {
	for {
		var batchstore leveldbstore.LevelDBStore
		batchstore = *DefStore

		if uint32(len(leafsCache)) >= DefConfig.BatchNum {
			sendl := leafsCache[0:DefConfig.BatchNum]
			log.Debugf("cache full. leafsCache len %d", len(leafsCache))
			ledgerAppendTxRoll(batchstore, sendl)
			leafsCache = leafsCache[DefConfig.BatchNum:]
		} else if clean {
			if uint32(len(leafsCache)) != 0 {
				ledgerAppendTxRoll(batchstore, leafsCache)
				leafsCache = make([]common.Uint256, 0)
			}
			break
		} else {
			break
		}
	}

	return leafsCache
}

func cacheLeafs() {
	wg.Add(1)
	defer wg.Done()

	var leafsCache []common.Uint256
	leafsCache = make([]common.Uint256, 0)

	seconds := time.Duration(DefConfig.CacheTime)

	for {
		select {
		case <-cacheQuitChannel:
			SystemOutOfService = true
			leafsCache = runleafs(leafsCache, true)
			return
		case t := <-cacheChannel:
			leafsCache = append(leafsCache, t.Leafs...)
			leafsCache = runleafs(leafsCache, SystemOutOfService)
		case <-time.After(time.Second * seconds):
			leafsCache = runleafs(leafsCache, true)
		}
	}
}

func ledgerAppendTx(store leveldbstore.LevelDBStore, leafv []common.Uint256) error {
	store.NewBatch()
	tx, err := constructTransation(DefSdk, leafv)
	if err != nil {
		return err
	}

	err = putTransaction(&store, tx)
	if err != nil {
		return err
	}

	addHashes := make([]common.Uint256, 0, 1)
	addHashes = append(addHashes, tx.Hash())
	TxStore.UpdateSelfToBatch(&store, addHashes)

	err = store.BatchCommit()
	if err != nil {
		return err
	}

	TxStore.PublishAddHashes(addHashes)

	return nil
}

func ledgerAppendTxRoll(store leveldbstore.LevelDBStore, leafv []common.Uint256) error {
	err := ledgerAppendTx(store, leafv)
	if err != nil {
		log.Infof("ledgerAppendTxRoll err : %s", err)
		for i := uint32(0); i < uint32(len(leafv)); i++ {
			delLeafIndex(DefStore, leafv[i])
		}
	}

	return err
}

func RoutineOfBatchAdd(leafv []common.Uint256) error {
	var store leveldbstore.LevelDBStore
	store = *DefStore
	store.NewBatch()

	wg.Add(1)
	defer wg.Done()

	store.NewBatch()

	var tx *types.MutableTransaction
	var err error
	// only batchnum construct tx
	addHashes := make([]common.Uint256, 0, 1)
	if uint32(len(leafv)) == DefConfig.BatchNum {
		tx, err = constructTransation(DefSdk, leafv)
		if err != nil {
			return err
		}

		err = putTransaction(&store, tx)
		if err != nil {
			return err
		}

		// if duplicate will drop batch.
		addHashes = append(addHashes, tx.Hash())
		TxStore.UpdateSelfToBatch(&store, addHashes)
	}

	// only lock the duplicate logic
	Existlock.Lock()
	defer Existlock.Unlock()

	for i := uint32(0); i < uint32(len(leafv)); i++ {
		_, err := getLeafIndex(&store, leafv[i])
		if err == nil {
			return errors.New("duplicate hash leafs. please check.")
		}
		putLeafIndex(&store, leafv[i], math.MaxUint32)
	}

	// this must be lock.
	err = store.BatchCommit()
	if err != nil {
		return err
	}

	// send to cache.
	if uint32(len(leafv)) != DefConfig.BatchNum {
		leafs := cacheCh{
			Leafs: leafv,
		}
		cacheChannel <- leafs
		return nil
	}

	TxStore.PublishAddHashes(addHashes)

	return nil
}

func leafvFromTx(tx *types.MutableTransaction) ([]common.Uint256, error) {
	source := common.NewZeroCopySource(tx.Payload.(*payload.InvokeCode).Code)
	contract := &states.WasmContractParam{}
	err := contract.Deserialization(source)
	if err != nil {
		return nil, err
	}

	raw := contract.Args
	sourceh := common.NewZeroCopySource(raw)
	method, _, irregular, eof := sourceh.NextString()
	argsNum, _, irregular, eof := sourceh.NextVarUint() // argNum is leaf vector len.
	if irregular || eof || method != "batch_add" {
		return nil, fmt.Errorf("leafvFromTx error irregular: %v, eof : %v, method: %s, argsNum: %d", irregular, eof, method, argsNum)
	}

	res := make([]common.Uint256, 0)
	for {
		h, eof := sourceh.NextHash()
		if eof {
			break
		}
		res = append(res, h)
	}

	if int(argsNum) != len(res) {
		return nil, fmt.Errorf("argsNum error: require %d, acctual %d", int(argsNum), len(res))
	}

	return res, nil
}

func AtomicSimulationBarrier() {
	var n int32
	atomic.AddInt32(&n, 1)
}

var (
	SendTxChannel chan bool
)

func RoutineOfSendTx() {
	for {
		if SystemOutOfService {
			return
		}

		time.Sleep(time.Second * time.Duration(DefConfig.SendTxInterval))

		TxStore.Txhashes.Range(func(k, v interface{}) bool {
			res, err := SendTxIter(k)
			if SystemOutOfService {
				return false
			}

			if res && err != nil {
				log.Warnf("RoutineOfSendTx: %s", err)
				time.Sleep(time.Second * time.Duration(DefConfig.SendTxInterval))
			}

			if !res {
				log.Warnf("RoutineOfSendTx: %s", err)
				return false
			}

			select {
			case <-SendTxChannel:
			case <-time.After(time.Second * time.Duration(DefConfig.SendTxInterval)):
			}

			return true
		})
	}
}

func SendTxIter(k interface{}) (bool, error) {
	var store leveldbstore.LevelDBStore
	store = *DefStore

	if SystemOutOfService {
		return false, nil
	}

	txh, ok := k.(common.Uint256)
	if !ok {
		log.Errorf("RoutineOfSendTx, sync map key is not hash type")
		SystemOutOfService = true
		return false, fmt.Errorf("RoutineOfSendTx, sync map key is not hash type")
	}

	AtomicSimulationBarrier()

	tx, err := getTransaction(&store, txh)
	if err != nil {
		log.Errorf("RoutineOfSendTx: %s", err)
		SystemOutOfService = true
		return false, err
	}
	_, err = leafvFromTx(tx)
	if err != nil {
		log.Errorf("RoutineOfSendTx: %s", err)
		SystemOutOfService = true
		return false, err
	}

	_, err = DefSdk.SendTransaction(tx)
	if err != nil {
		return true, err
	}

	return true, nil
}

func GetProof(store *leveldbstore.LevelDBStore, leaf_hash common.Uint256, treeSize uint32) ([]common.Uint256, error) {
	index, err := getLeafIndex(store, leaf_hash)
	if err != nil {
		return nil, err
	}

	log.Debugf("leaf %x index %d\n", leaf_hash, index)

	MTlock.RLock()
	defer MTlock.RUnlock()
	return DefMerkleTree.InclusionProof(index, treeSize)
}

type VerifyResult struct {
	Root        common.Uint256   `json:"root"`
	TreeSize    uint32           `json:"size"`
	BlockHeight uint32           `json:"blockheight"`
	Index       uint32           `json:"index"`
	Proof       []common.Uint256 `json:"proof"`
}

func (self VerifyResult) MarshalJSON() ([]byte, error) {
	root := hex.EncodeToString(self.Root[:])
	proof := make([]string, 0, len(self.Proof))
	for i := range self.Proof {
		proof = append(proof, hex.EncodeToString(self.Proof[i][:]))
	}

	res := struct {
		Root        string   `json:"root"`
		TreeSize    uint32   `json:"size"`
		BlockHeight uint32   `json:"blockheight"`
		Index       uint32   `json:"index"`
		Proof       []string `json:"proof"`
	}{
		Root:        root,
		TreeSize:    self.TreeSize,
		BlockHeight: self.BlockHeight,
		Index:       self.Index,
		Proof:       proof,
	}

	return json.Marshal(res)
}

func (self *VerifyResult) UnmarshalJSON(buf []byte) error {
	res := struct {
		Root        string   `json:"root"`
		TreeSize    uint32   `json:"size"`
		BlockHeight uint32   `json:"blockheight"`
		Index       uint32   `json:"index"`
		Proof       []string `json:"proof"`
	}{}

	if len(buf) == 0 {
		return nil
	}

	json.Unmarshal(buf, &res)

	root, err := HashFromHexString(res.Root)
	if err != nil {
		return err
	}

	proof, err := convertParamsToLeafs(res.Proof)
	if err != nil {
		return err
	}

	self.Root = root
	self.TreeSize = res.TreeSize
	self.BlockHeight = res.BlockHeight
	self.Index = res.Index
	self.Proof = proof

	return nil
}

func Verify(store *leveldbstore.LevelDBStore, leaf common.Uint256, root common.Uint256, treeSize uint32) ([]common.Uint256, uint32, error) {
	proof, err := GetProof(store, leaf, treeSize)
	if err != nil {
		return nil, 0, err
	}
	verify := merkle.NewMerkleVerifier()

	index, err := getLeafIndex(store, leaf)
	if err != nil {
		return nil, 0, err
	}

	err = verify.VerifyLeafHashInclusion(leaf, index, proof, root, treeSize)
	if err != nil {
		return nil, 0, err
	}

	return proof, index, nil
}

func main() {
	var isCPUPprof bool
	isCPUPprof = false
	if isCPUPprof {
		file, err := os.Create("./cpu.pprof")
		if err != nil {
			log.Errorf("create cpu file %s", err)
			return
		}
		pprof.StartCPUProfile(file)
		defer pprof.StopCPUProfile()
	}
	if err := setupAPP().Run(os.Args); err != nil {
		os.Exit(1)
	}
}

var (
	ConfigFlag = cli.StringFlag{
		Name:  "config,c",
		Usage: "the contract filename to be tested.",
	}
	LogLevelFlag = cli.UintFlag{
		Name:  "loglevel,l",
		Usage: "set the log levela.",
		Value: log.InfoLog,
	}
)

func setupAPP() *cli.App {
	app := cli.NewApp()
	app.Usage = "ogqServer"
	app.UsageText = "ogq [option] input"
	app.Action = startOGQServer
	app.Version = "1.0.0"
	app.Copyright = "Copyright in 2019 The Ontology Authors"
	app.Flags = []cli.Flag{
		ConfigFlag,
		LogLevelFlag,
	}
	app.Before = func(context *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		return nil
	}

	app.ExitErrHandler = func(context *cli.Context, err error) {
		if err != nil {
			log.Fatalf("%v", err)
		}
	}
	return app
}

func initConfig(ctx *cli.Context) error {
	if ctx.IsSet(utils.GetFlagName(ConfigFlag)) {
		configFileName := ctx.String(utils.GetFlagName(ConfigFlag))
		configBuff, err := ioutil.ReadFile(configFileName)
		if err != nil {
			return err
		}
		err = json.Unmarshal([]byte(configBuff), &DefConfig)
		if err != nil {
			return err
		}
		log.Debugf("%v", &DefConfig)
		if DefConfig.ServerPort == 0 || DefConfig.CacheTime == 0 || len(DefConfig.Walletname) == 0 || len(DefConfig.SignerAddress) == 0 || len(DefConfig.OntNode) == 0 || len(DefConfig.ContracthexAddr) == 0 || len(DefConfig.Authorize) == 0 || DefConfig.BatchNum == 0 || DefConfig.SendTxInterval == 0 || DefConfig.TryChainInterval == 0 || DefConfig.SendTxSize == 0 {
			return errors.New("config not set ok")
		}

		return nil
	}

	return errors.New("config not set")
}

func startOGQServer(ctx *cli.Context) error {
	LogLevel := ctx.Uint(utils.GetFlagName(LogLevelFlag))
	log.InitLog(int(LogLevel), log.PATH, log.Stdout)

	err := initConfig(ctx)
	if err != nil {
		return err
	}

	err = InitSigner()
	if err != nil {
		return err
	}

	err = InitCompactMerkleTree()
	if err != nil {
		return err
	}

	err = initRPCServer()
	if err != nil {
		return err
	}

	go RoutineOfSendTx()
	go RoutineOfAddToLocalStorage()

	waitToExit(ctx)

	return nil
}

func initRPCServer() error {
	var err error
	exitCh := make(chan interface{}, 0)
	go func() {
		err = StartRPCServer()
		close(exitCh)
	}()

	flag := false
	select {
	case <-exitCh:
		if !flag {
			return err
		}
	case <-time.After(time.Millisecond * 5):
		flag = true
	}
	log.Infof("Rpc init success")
	return nil
}

func StartRPCServer() error {
	http.HandleFunc("/", RpcHandle)

	err := http.ListenAndServe(":"+strconv.Itoa(DefConfig.ServerPort), nil)
	if err != nil {
		return fmt.Errorf("ListenAndServe error:%s", err)
	}
	return nil
}

func convertParamsToLeafs(params []string) ([]common.Uint256, error) {
	leafs := make([]common.Uint256, len(params), len(params))

	for i := uint32(0); i < uint32(len(params)); i++ {
		s := params[i]
		leaf, err := HashFromHexString(s)
		if err != nil {
			return nil, err
		}
		leafs[i] = leaf
	}

	return leafs, nil
}

func rpcVerify(vargs *RpcParam) map[string]interface{} {
	if SystemOutOfService {
		return responsePack(NODE_OUTSERVICE, "Out of Service")
	}

	if len(vargs.Hashes) != 1 {
		return responsePack(INVALID_PARAM, nil)
	}

	pubkey, _, err := getPublicSigData(vargs.PubKey, "")
	if err != nil {
		log.Infof("%s", err)
		return responsePack(INVALID_PARAM, nil)
	}

	address := types.AddressFromPubKey(pubkey)
	if !checkAuthorizeOfAddress(address) {
		return responsePack(NO_AUTH, nil)
	}

	leaf, err := HashFromHexString(vargs.Hashes[0])
	if err != nil {
		log.Infof("Verify convert params err: %s\n", err)
		return responsePack(INVALID_PARAM, nil)
	}

	var root common.Uint256
	var treeSize uint32
	var blockheight uint32

	MTlock.RLock()
	root = DefMerkleTree.Root()
	treeSize = DefMerkleTree.TreeSize()
	blockheight, err = getRootBlockHeight(DefStore, root)
	MTlock.RUnlock()

	proof, index, err := Verify(DefStore, leaf, root, treeSize)
	if err != nil {
		log.Debugf("verify failed %s", err)
		return responsePack(VERIFY_FAILED, nil)
	}

	if err != nil {
		log.Debugf("get blockheight failed, %s", err)
		return responsePack(VERIFY_FAILED, nil)
	}
	res := VerifyResult{
		Root:        root,
		TreeSize:    treeSize,
		BlockHeight: blockheight,
		Index:       index,
		Proof:       proof,
	}

	log.Debugf("Verify leaf ok :%x, root:%x, treeSize: %d\n", leaf, root, treeSize)

	return responseSuccess(res)
}

// arg[0] pubkey serialization data. arg[1] sigData
func getPublicSigData(pubs string, sigs string) (keypair.PublicKey, []byte, error) {
	raw, err := common.HexToBytes(pubs)
	if err != nil {
		return nil, nil, err
	}

	pubkey, err := keypair.DeserializePublicKey(raw)
	if err != nil {
		return nil, nil, errors.New("DeserializePublicKey failed.")
	}

	sigData, err := common.HexToBytes(sigs)
	if err != nil {
		return nil, nil, err
	}

	return pubkey, sigData, nil
}

const maxDeclineNum uint32 = 512

func rpcBatchAdd(addargs *RpcParam) map[string]interface{} {
	if SystemOutOfService {
		return responsePack(NODE_OUTSERVICE, "Out of Service")
	}

	pubkey, sigData, err := getPublicSigData(addargs.PubKey, addargs.Sigature)
	if err != nil {
		log.Infof("%s", err)
		return responsePack(INVALID_PARAM, err.Error())
	}

	address := types.AddressFromPubKey(pubkey)
	if !checkAuthorizeOfAddress(address) {
		return responsePack(NO_AUTH, "pubkey do not have authorize.")
	}

	params := addargs.Hashes

	if uint32(len(params)) > maxDeclineNum || uint32(len(params)) == 0 {
		log.Errorf("too much elemet. most %d. or empty.", maxDeclineNum)
		return responsePack(INVALID_PARAM, "too much or empty hashes")
	}

	hashes, err := convertParamsToLeafs(params)
	if err != nil {
		log.Infof("batch add convert params err: %s\n", err)
		return responsePack(INVALID_PARAM, err.Error())
	}

	err = signature.Verify(pubkey, hashes[0][:], sigData)
	if err != nil {
		return responsePack(NO_AUTH, "Verify failed. sigData not right.")
	}

	err = RoutineOfBatchAdd(hashes)
	if err != nil {
		log.Infof("batch add failed %s\n", err)
		return responsePack(ADDHASH_FAILED, err.Error())
	}

	if DefConfig.BatchAddSleepTime != 0 {
		time.Sleep(time.Second * time.Duration(DefConfig.BatchAddSleepTime))
	}

	return responseSuccess("Cached Success")
}

func responseSuccess(result interface{}) map[string]interface{} {
	return responsePack(SUCCESS, result)
}

func responsePack(errcode int64, result interface{}) map[string]interface{} {
	resp := map[string]interface{}{
		"error":  errcode,
		"desc":   ErrMap[errcode],
		"result": result,
	}
	return resp
}

func waitToExit(ctx *cli.Context) {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			log.Infof("OGQ server received exit signal: %v.", sig.String())
			SystemOutOfService = true
			cacheQuitChannel <- true
			close(SendTxChannel)
			wg.Wait()
			log.Info("Now exit")

			var batchstore leveldbstore.LevelDBStore
			batchstore = *DefStore
			batchstore.NewBatch()
			SaveCompactMerkleTree(DefMerkleTree, &batchstore)
			TxStore.UpdateSelfToBatch(&batchstore, nil)
			err := batchstore.BatchCommit()
			if err != nil {
				log.Errorf("%s", err)
			}
			log.Info("save data ok")

			DefStore.Close()
			close(exit)
			break
		}
	}()
	<-exit
}

func clean() {
	os.RemoveAll(levelDBName)
	os.RemoveAll(fileHashStoreName)
	os.RemoveAll(log.PATH)
}

type memHashStore struct {
	Hashes []common.Uint256
}

// NewMemHashStore returns a HashStore implement in memory
func NewMemHashStore() *memHashStore {
	return &memHashStore{}
}

func (self *memHashStore) Append(hash []common.Uint256) error {
	self.Hashes = append(self.Hashes, hash...)
	return nil
}

func (self *memHashStore) GetHash(pos uint32) (common.Uint256, error) {
	return self.Hashes[pos], nil
}

func (self *memHashStore) Flush() error {
	return nil
}

func (self *memHashStore) Close() {}

func HashFromHexString(s string) (common.Uint256, error) {
	hx, err := common.HexToBytes(s)
	if err != nil {
		return merkle.EMPTY_HASH, err
	}
	res, err := common.Uint256ParseFromBytes(hx)
	if err != nil {
		return merkle.EMPTY_HASH, err
	}
	return res, nil
}

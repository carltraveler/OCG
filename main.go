package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	sdk "github.com/ontio/ontology-go-sdk"

	"github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/store/leveldbstore"
	"github.com/ontio/ontology/core/types"
	utils2 "github.com/ontio/ontology/core/utils"
	"github.com/ontio/ontology/http/base/rpc"
	"github.com/ontio/ontology/merkle"
	"github.com/ontio/ontology/smartcontract/states"
	"github.com/urfave/cli"
)

type DataPrefix byte

const (
	PREFIX_INDEX       DataPrefix = 0x1
	PREFIX_MERKLE_TREE DataPrefix = 0x2
	PREFIX_TX          DataPrefix = 0x3
	PREFIX_TX_HASH     DataPrefix = 0x4
)

const (
	levelDBName       string = "leveldb"
	fileHashStoreName string = "filestore.db"
	BATCHNUM          uint32 = 512
)

var (
	contractAddress common.Address
)

const (
//walletname      string = "./wallet.dat"
//walletpassword  string = "123456"
//ontNode         string = "http://localhost:20336"
//signerAddress   string = "APHNPLz2u1JUXyD8rhryLaoQrW46J3P6y2"
//serverPort      int    = 32339
//contracthexAddr string = "8ce5b4c91f89aa72662d5fa9db5ee642b57dfd05"
)

type ServerConfig struct {
	Walletname      string `json:"walletname"`
	Walletpassword  string `json:"walletpassword"`
	OntNode         string `json:"ontnode"`
	SignerAddress   string `json:"signeraddress"`
	ServerPort      int    `json:"serverport"`
	ContracthexAddr string `json:"contracthexaddr"`
}

const (
	SUCCESS        int64 = 0
	INVALID_PARAM  int64 = 41001
	ADDHASH_FAILED int64 = 41002
)

var ErrMap = map[int64]string{
	SUCCESS:        "SUCCESS",
	INVALID_PARAM:  "INVALID_PARAM",
	ADDHASH_FAILED: "ADDHASH_FAILED",
}

type TransactionStore struct {
	lock     sync.Mutex
	Txhashes map[common.Uint256]bool
}

func (self *TransactionStore) AppendTxToStore(tx *types.MutableTransaction, store *leveldbstore.LevelDBStore) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	err := putTransaction(store, tx)
	if err != nil {
		return err
	}
	self.Txhashes[tx.Hash()] = true
	return nil
}

func (self *TransactionStore) GetTxFromStore(txh common.Uint256, store *leveldbstore.LevelDBStore) (*types.MutableTransaction, error) {
	self.lock.Lock()
	defer self.lock.Unlock()

	tx, err := getTransaction(store, txh)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func (self *TransactionStore) DeleteTxStore(h common.Uint256, store *leveldbstore.LevelDBStore) {
	self.lock.Lock()
	defer self.lock.Unlock()
	delete(self.Txhashes, h)
	delTransaction(store, h)
}

func (self *TransactionStore) UpdateSelfToStore(store *leveldbstore.LevelDBStore) {
	self.lock.Lock()
	defer self.lock.Unlock()
	sink := common.NewZeroCopySink(nil)
	for k, _ := range self.Txhashes {
		sink.WriteHash(k)
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
		self.Txhashes[h] = true
	}
}

var (
	DefStore      *leveldbstore.LevelDBStore
	DefMerkleTree *merkle.CompactMerkleTree
	DefSdk        *sdk.OntologySdk
	MTlock        *sync.RWMutex
	Existlock     *sync.Mutex
	TxStore       *TransactionStore
	wg            sync.WaitGroup
	DefConfig     ServerConfig
	DefSigner     sdk.Signer
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

	DefSigner, err = wallet.GetAccountByAddress(DefConfig.SignerAddress, []byte(DefConfig.Walletpassword))
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

	DefMerkleTree = merkle.NewTree(cMTree.TreeSize(), cMTree.Hashes(), store)
	MTlock = new(sync.RWMutex)
	Existlock = new(sync.Mutex)

	contractAddress, err = common.AddressFromHexString(DefConfig.ContracthexAddr)
	if err != nil {
		return err
	}

	TxStore = &TransactionStore{
		Txhashes: make(map[common.Uint256]bool),
	}

	raw, err := DefStore.Get(GetKeyByHash(PREFIX_TX_HASH, merkle.EMPTY_HASH))
	if err == nil {
		TxStore.UnMarshal(raw)
	}

	DefSdk = sdk.NewOntologySdk()
	DefSdk.NewRpcClient().SetAddress(DefConfig.OntNode)

	go TxStoreTimeChecker(DefSdk, DefMerkleTree, DefStore)
	return nil
}

func SaveCompactMerkleTree(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore) {
	rawTree, _ := cMtree.Marshal()
	store.BatchPut(GetKeyByHash(PREFIX_MERKLE_TREE, merkle.EMPTY_HASH), rawTree)
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

func putLeafIndex(store *leveldbstore.LevelDBStore, leaf common.Uint256, index uint32) {
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint32(index)
	store.BatchPut(GetKeyByHash(PREFIX_INDEX, leaf), sink.Bytes())
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

func constructTransation(ontSdk *sdk.OntologySdk, leafv []common.Uint256) (*types.MutableTransaction, error) {
	if uint32(len(leafv)) > BATCHNUM {
		return nil, fmt.Errorf("too much elemet. most %d.", BATCHNUM)
	}

	args := make([]interface{}, 2)
	params := make([]interface{}, len(leafv))
	for i := range leafv {
		params[i] = leafv[i]
	}
	args[0] = "batch_add"
	args[1] = params

	tx, err := utils2.NewWasmVMInvokeTransaction(0, 8000000, contractAddress, args)
	if err != nil {
		return nil, fmt.Errorf("create tx failed: %s", err)
	}
	err = ontSdk.SignToTransaction(tx, DefSigner)
	if err != nil {
		return nil, fmt.Errorf("signer tx failed: %s", err)
	}

	return tx, nil
}

func invokeWasmContract(ontSdk *sdk.OntologySdk, tx *types.MutableTransaction) (common.Uint256, uint32, error) {
	txHash, err := ontSdk.SendTransaction(tx)
	if err != nil {
		return merkle.EMPTY_HASH, 0, fmt.Errorf("send tx failed: %s", err)
	}

	log.Debugf("tx hash : %s", txHash.ToHexString())

	_, err = ontSdk.WaitForGenerateBlock(30 * time.Second)
	if err != nil {
		return merkle.EMPTY_HASH, 0, fmt.Errorf("error in WaitForGenerateBlock:%s\n", err)
	}

	events, err := ontSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		return merkle.EMPTY_HASH, 0, fmt.Errorf("error in GetSmartContractEvent:%s\n", err)
	}

	// here Transaction success.
	if events.State == 0 {
		return merkle.EMPTY_HASH, 0, fmt.Errorf("error in events.State is 0 failed.\n")
	}

	if len(events.Notify) != 1 {
		log.Errorf("notify should be len 1, len: %d\n", len(events.Notify))
	}

	var newroot common.Uint256
	var treeSize uint32
	switch val := events.Notify[0].States.(type) {
	case []interface{}:
		if len(val) != 2 {
			log.Errorf("states len should be len 2, len: %d\n", len(val))
		}

		newroot, err = common.Uint256FromHexString(val[0].(string))
		if err != nil {
			log.Errorf("notify return err %s\n", err)
		}

		t, err := strconv.Atoi(val[1].(string))
		if err != nil {
			log.Errorf("notify return err %s\n", err)
		}
		treeSize = uint32(t)
	default:
		log.Errorf("notify supported type err %s\n", reflect.TypeOf(events.Notify[0].States))
	}

	for _, notify := range events.Notify {
		log.Debugf("%+v\n", notify)
	}

	log.Debugf("newroot: %x, treeSize: %d\n", newroot, treeSize)

	return newroot, treeSize, nil
}

// duplicate handle
// contract failed handle
func BatchAdd(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore, leafv []common.Uint256) error {
	Existlock.Lock()
	defer Existlock.Unlock()
	wg.Add(1)
	defer wg.Done()

	store.NewBatch()

	if uint32(len(leafv)) > BATCHNUM {
		return fmt.Errorf("too much elemet. most %d.", BATCHNUM)
	}

	// check duplicate. and construct transaction.
	for i := uint32(0); i < uint32(len(leafv)); i++ {
		_, err := getLeafIndex(store, leafv[i])
		if err == nil {
			return errors.New("duplicate hash leafs. please check.")
		}
	}

	tx, err := constructTransation(DefSdk, leafv)
	if err != nil {
		return err
	}

	err = TxStore.AppendTxToStore(tx, store)
	if err != nil {
		return err
	}

	for i := uint32(0); i < uint32(len(leafv)); i++ {
		// here use index marked as exist. the right index will put later.
		log.Debugf("BatchAdd leaf[%d]: %x\n", i, leafv[i])
		putLeafIndex(store, leafv[i], math.MaxUint32)
	}

	err = store.BatchCommit()
	if err != nil {
		return err
	}

	// here batch. so be carefull of multi routing issue with newbatch
	var newstore leveldbstore.LevelDBStore
	newstore = *store

	go addLeafsToStorage(DefSdk, cMtree, &newstore, leafv, tx)

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
		return nil, fmt.Errorf("leafvFromTx error irregular: %d, eof : %d, method: %s, argsNum: %d", irregular, eof, method, argsNum)
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

func TxStoreTimeChecker(ontSdk *sdk.OntologySdk, cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore) {
	for {
		time.Sleep(time.Second * 30)
		log.Debugf("TimerChecker running")

		MTlock.Lock()

		for k, _ := range TxStore.Txhashes {
			//sink.WriteHash(k)
			tx, err := TxStore.GetTxFromStore(k, store)
			if err != nil {
				log.Errorf("TimerChecker: txhash: %x,impossible get tx error. %s", k, err)
				MTlock.Unlock()
				return
			}
			leafv, err := leafvFromTx(tx)
			if err != nil {
				log.Errorf("TimerChecker: impossible get leafv error. %s", err)
				MTlock.Unlock()
				return
			}

			for i := range leafv {
				log.Debugf("TimerChecker: leafv[%d]: %x\n", i, leafv[i])
			}

			go addLeafsToStorage(ontSdk, cMtree, store, leafv, tx)
		}
		MTlock.Unlock()
	}
}

func addLeafsToStorage(ontSdk *sdk.OntologySdk, cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore, leafv []common.Uint256, tx *types.MutableTransaction) {
	MTlock.Lock()
	defer MTlock.Unlock()
	wg.Add(1)
	defer wg.Done()
	store.NewBatch()

	// check already handled by another gorouting
	index, err := getLeafIndex(store, leafv[0])
	if index != math.MaxUint32 {
		return
	}

	for i := uint32(0); i < uint32(len(leafv)); i++ {
		log.Debugf("addLeafsToStorage: leafv[%d]: %x", i, leafv[i])
	}

	callCount := 0
	var newroot common.Uint256
	var treeSize uint32

	// must the same seq with contract. so here use lock to ensure atomic.
	for {
		newroot, treeSize, err = invokeWasmContract(ontSdk, tx)
		callCount++
		if err != nil {
			if callCount > 3 {
				log.Debugf("call contract failed %s", err)
				return
			}
			continue
		}

		break
	}

	tmpTree := &merkle.CompactMerkleTree{}
	rawtree, _ := cMtree.Marshal()
	tmpTree.UnMarshal(rawtree)
	for i := uint32(0); i < uint32(len(leafv)); i++ {
		tmpTree.AppendHash(leafv[i])
	}

	if newroot != tmpTree.Root() || treeSize != tmpTree.TreeSize() {
		panic(fmt.Errorf("chainroot: %x, root : %x, chaintreeSize: %d, treeSize: %d", newroot, cMtree.Root(), treeSize, cMtree.TreeSize()))
	}

	// than mark the tx resolved. once tx mark resolved. cMtree must store to local.
	for i := uint32(0); i < uint32(len(leafv)); i++ {
		// update index. zero based.
		putLeafIndex(store, leafv[i], cMtree.TreeSize()-1)
	}

	log.Debugf("root: %x, treeSize: %d", cMtree.Root(), cMtree.TreeSize())

	// transaction success
	TxStore.DeleteTxStore(tx.Hash(), store)
	TxStore.UpdateSelfToStore(store)
	SaveCompactMerkleTree(cMtree, store)
	err = store.BatchCommit()
	if err != nil {
		panic(err)
	}

	for i := uint32(0); i < uint32(len(leafv)); i++ {
		cMtree.AppendHash(leafv[i])
	}
}

func GetProof(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore, leaf_hash common.Uint256, treeSize uint32) ([]common.Uint256, error) {
	index, err := getLeafIndex(store, leaf_hash)
	if err != nil {
		return nil, err
	}

	return cMtree.InclusionProof(index, treeSize)
}

type verifyResult struct {
	exist bool
	err   error
}

func Verify(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore, responseCh chan<- verifyResult, leaf common.Uint256, root common.Uint256, treeSize uint32) {
	MTlock.RLock()
	defer MTlock.RUnlock()

	proof, err := GetProof(cMtree, store, leaf, treeSize)
	if err != nil {
		responseCh <- verifyResult{
			exist: false,
			err:   err,
		}
		return
	}
	verify := merkle.NewMerkleVerifier()

	index, err := getLeafIndex(store, leaf)
	if err != nil {
		responseCh <- verifyResult{
			exist: false,
			err:   err,
		}
		return
	}

	err = verify.VerifyLeafHashInclusion(leaf, index, proof, root, treeSize)
	if err != nil {
		responseCh <- verifyResult{
			exist: false,
			err:   err,
		}
		return
	}

	responseCh <- verifyResult{
		exist: true,
		err:   err,
	}
	return
}

func main() {
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

	err = InitCompactMerkleTree()
	if err != nil {
		return err
	}

	err = InitSigner()
	if err != nil {
		return err
	}

	err = initRPCServer()
	if err != nil {
		return err
	}

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
	http.HandleFunc("/", rpc.Handle)

	rpc.HandleFunc("verify", rpcVerify)
	rpc.HandleFunc("batch_add", rpcBatchAdd)

	err := http.ListenAndServe(":"+strconv.Itoa(DefConfig.ServerPort), nil)
	if err != nil {
		return fmt.Errorf("ListenAndServe error:%s", err)
	}
	return nil
}

func convertParamsToHex(params []interface{}) ([]byte, bool) {
	if len(params) != 1 {
		return nil, true
	}

	s, ok := params[0].(string)
	if !ok {
		return nil, true
	}

	hx, err := common.HexToBytes(s)
	if err != nil {
		return nil, true
	}
	return hx, false
}

func rpcVerify(params []interface{}) map[string]interface{} {
	hx, err := convertParamsToHex(params)
	if err {
		log.Debugf("Verify convert params err: %s\n", err)
		return responsePack(INVALID_PARAM, "")
	}

	source := common.NewZeroCopySource(hx)
	leaf, eof := source.NextHash()
	root, eof := source.NextHash()
	treeSize, eof := source.NextUint32()
	if eof {
		log.Debugf("Verify param less than require")
		return responsePack(INVALID_PARAM, "")
	}
	// check do not have more byte. accurate to match the args.
	_, eof = source.NextByte()
	if !eof {
		log.Debugf("Verify param len overflow")
		return responsePack(INVALID_PARAM, "")
	}

	responseCh := make(chan verifyResult)
	go Verify(DefMerkleTree, DefStore, responseCh, leaf, root, treeSize)

	res := <-responseCh

	//res, msg := Verify(DefMerkleTree, DefStore, responseCh, leaf, root, treeSize)
	log.Infof("Verify leaf :%x, root:%x, treeSize: %d, exist: %d, msg: %s\n", leaf, root, treeSize, res.exist, res.err)

	return responseSuccess(res)
}

func rpcBatchAdd(params []interface{}) map[string]interface{} {
	hx, err := convertParamsToHex(params)
	if err {
		log.Debugf("batch add convert params err: %s\n", err)
		return responsePack(INVALID_PARAM, "")
	}

	source := common.NewZeroCopySource(hx)
	if (source.Size() % common.UINT256_SIZE) != 0 {
		log.Debugf("batchadd args len not mod by UINT256_SIZE, len: %d\n", source.Size())
		return responsePack(INVALID_PARAM, "")
	}

	hashes := make([]common.Uint256, 0)
	leaf, eof := source.NextHash()
	if eof {
		log.Debug("batchadd args len less UINT256_SIZE\n")
		return responsePack(INVALID_PARAM, "")
	}
	hashes = append(hashes, leaf)
	for {
		leaf, eof = source.NextHash()
		if eof {
			break
		}
		hashes = append(hashes, leaf)
	}

	// can not partial add. chain will not save to storage if contract exec failed.
	ok := BatchAdd(DefMerkleTree, DefStore, hashes)
	if ok != nil {
		log.Debugf("batch add failed %s\n", ok)
		return responsePack(ADDHASH_FAILED, "")
	}

	return responseSuccess("Add Success")
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
			wg.Wait()
			log.Info("Now exit")
			MTlock.Lock()
			DefStore.NewBatch()
			SaveCompactMerkleTree(DefMerkleTree, DefStore)
			TxStore.UpdateSelfToStore(DefStore)
			err := DefStore.BatchCommit()
			if err != nil {
				log.Errorf("%s", err)
			}
			MTlock.Unlock()

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

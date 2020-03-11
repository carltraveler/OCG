package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/ontio/ontology/cmd/utils"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/core/store/leveldbstore"
	"github.com/ontio/ontology/http/base/rpc"
	"github.com/ontio/ontology/merkle"
	"github.com/urfave/cli"
)

type DataPrefix byte

const (
	PREFIX_INDEX       DataPrefix = 0x1
	PREFIX_MERKLE_TREE DataPrefix = 0x2
)

const (
	levelDBName       string = "leveldb"
	fileHashStoreName string = "filestore.db"
)

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

var DefStore *leveldbstore.LevelDBStore
var DefMerkleTree *merkle.CompactMerkleTree

func GetKeyByHash(prefix DataPrefix, h common.Uint256) []byte {
	sink := common.NewZeroCopySink(nil)
	sink.WriteByte(byte(prefix))
	sink.WriteHash(h)
	return sink.Bytes()
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
		cMTree.UnMarshal(rawTree)
	}

	store, err := merkle.NewFileHashStore(fileHashStoreName, cMTree.TreeSize())
	if err != nil {
		return err
	}

	DefMerkleTree = merkle.NewTree(cMTree.TreeSize(), cMTree.Hashes(), store)
	return nil
}

func SaveCompactMerkleTree(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore) {
	rawTree, _ := cMtree.Marshal()
	store.Put(GetKeyByHash(PREFIX_MERKLE_TREE, merkle.EMPTY_HASH), rawTree)
}

func putLeafIndex(store *leveldbstore.LevelDBStore, leaf common.Uint256, index uint32) {
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint32(index)
	store.Put(GetKeyByHash(PREFIX_INDEX, leaf), sink.Bytes())
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

// duplicate handle
// contract failed handle
func BatchAdd(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore, leafv []common.Uint256) error {
	// call contract to onchain. server drop it if contract operation failed. here should wait contract run over.

	// after contract added. added to local. compare root with chain root.
	for i := uint32(0); i < uint32(len(leafv)); i++ {
		cMtree.AppendHash(leafv[i])
		// index zero based.
		putLeafIndex(store, leafv[i], cMtree.TreeSize()-1)
	}

	return nil
}

func GetProof(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore, leaf_hash common.Uint256, treeSize uint32) ([]common.Uint256, error) {
	index, err := getLeafIndex(store, leaf_hash)
	if err != nil {
		return nil, err
	}

	return cMtree.InclusionProof(index, treeSize)
}

func Verify(cMtree *merkle.CompactMerkleTree, store *leveldbstore.LevelDBStore, leaf common.Uint256, root common.Uint256, treeSize uint32) (bool, error) {
	proof, err := GetProof(cMtree, store, leaf, treeSize)
	if err != nil {
		return false, err
	}
	verify := merkle.NewMerkleVerifier()

	index, err := getLeafIndex(store, leaf)
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
	if err := setupAPP().Run(os.Args); err != nil {
		os.Exit(1)
	}
}

var (
	ConfigFlag = cli.StringFlag{
		Name:  "config,c",
		Usage: "the contract filename to be tested.",
	}
	ContractParamsFlag = cli.StringFlag{
		Name:  "param,p",
		Usage: "specify contract param when input is a file.",
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
		ContractParamsFlag,
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

func startOGQServer(ctx *cli.Context) error {
	LogLevel := ctx.Uint(utils.GetFlagName(LogLevelFlag))
	log.InitLog(int(LogLevel), log.PATH, log.Stdout)

	err := InitCompactMerkleTree()
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

	err := http.ListenAndServe(":"+strconv.Itoa(int(32339)), nil)
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
		return responsePack(INVALID_PARAM, "")
	}
	// check do not have more byte. accurate to match the args.
	_, eof = source.NextByte()
	if !eof {
		return responsePack(INVALID_PARAM, "")
	}

	res, msg := Verify(DefMerkleTree, DefStore, leaf, root, treeSize)
	log.Infof("Verify leaf :%x, root:%x, treeSize: %d, msg: %s\n", leaf, root, treeSize, msg)

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
		log.Debug("batch add failed %s\n", ok)
		return responsePack(ADDHASH_FAILED, "")
	}

	log.Infof("batch added %d hash. after add merkle root:%x\n", len(hashes), DefMerkleTree.Root())

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
			SaveCompactMerkleTree(DefMerkleTree, DefStore)
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

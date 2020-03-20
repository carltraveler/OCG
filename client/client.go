package main

import "fmt"

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/merkle"
)

//JsonRpc version
const JSON_RPC_VERSION = "2.0"

//JsonRpcRequest object in rpc
type JsonRpcRequest struct {
	Version string        `json:"jsonrpc"`
	Id      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

//JsonRpcResponse object response for JsonRpcRequest
type JsonRpcResponse struct {
	Id     string          `json:"id"`
	Error  int64           `json:"error"`
	Desc   string          `json:"desc"`
	Result json.RawMessage `json:"result"`
}

//RpcClient for ontology rpc api
type RpcClient struct {
	qid        uint64
	addr       string
	httpClient *http.Client
}

//NewRpcClient return RpcClient instance
func NewRpcClient(addr string) *RpcClient {
	return &RpcClient{
		addr: addr,
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false, //enable keepalive
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
			},
			Timeout: time.Second * 300, //timeout for http response
		},
	}
}

//SetAddress set rpc server address. Simple http://localhost:20336
func (this *RpcClient) SetAddress(addr string) *RpcClient {
	this.addr = addr
	return this
}

func (this *RpcClient) GetNextQid() string {
	return fmt.Sprintf("%d", atomic.AddUint64(&this.qid, 1))
}

//sendRpcRequest send Rpc request to ontology
func (this *RpcClient) sendRpcRequest(qid, method string, params []interface{}) ([]byte, error) {
	rpcReq := &JsonRpcRequest{
		Version: JSON_RPC_VERSION,
		Id:      qid,
		Method:  method,
		Params:  params,
	}
	data, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("JsonRpcRequest json.Marsha error:%s", err)
	}
	resp, err := this.httpClient.Post(this.addr, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rpc response body error:%s", err)
	}
	rpcRsp := &JsonRpcResponse{}
	err = json.Unmarshal(body, rpcRsp)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal JsonRpcResponse:%s error:%s", body, err)
	}
	if rpcRsp.Error != 0 {
		return nil, fmt.Errorf("JsonRpcResponse error code:%d desc:%s result:%s", rpcRsp.Error, rpcRsp.Desc, rpcRsp.Result)
	}
	return rpcRsp.Result, nil
}

type verifyArg struct {
	Leafs []common.Uint256
	Root  []common.Uint256
	M     uint32
}

var (
	N uint32 = 255
)

func verifyleaf(client *RpcClient, leafs []common.Uint256) {
	for i := uint32(0); i < uint32(len(leafs)); i++ {
		vargs := getVerifyArgs(leafs[i])
		_, err := client.sendRpcRequest(client.GetNextQid(), "verify", vargs)
		if err != nil {
			fmt.Printf("Verify Failed %s\n", err)
			panic("xxx")
		}
		//fmt.Printf("Verify Success %s\n", string(res))
	}

}

func main() {
	defer clean()
	testUrl := "http://127.0.0.1:32339"
	client := NewRpcClient(testUrl)
	if true {
		numbatch := uint32(10000)
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
			//if m == numbatch-1 {
			//printLeafs("leafs", leafs)
			//}
			//root = getleafvroot(leafs, tree, false)
			//printLeafs("root", root)
			//tree.AppendHash(leafs[i])
			addArgs := leafvToAddArgs(leafs)
			//generateConArgs(leafs)
			//alladdargs = append(alladdargs, addArgs)
			//alladdargs[m] = addArgs
			//res, err := client.sendRpcRequest(client.GetNextQid(), "batchAdd", []interface{}{alladdargs[m]})
			verify := false

			if verify {

				_, err := client.sendRpcRequest(client.GetNextQid(), "batchAdd", addArgs)
				if err != nil {
					fmt.Printf("Add Error: %s\n", err)
					//return
				}
			} else {
				verifyleaf(client, leafs)
			}
		}
		fmt.Printf("prepare args done\n")
		fmt.Printf("root %x, treeSize %d\n", tree.Root(), tree.TreeSize())
	}
}

func waitToExit() {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			fmt.Printf("OGQ server received exit signal: %v.", sig.String())
			close(exit)
			break
		}
	}()
	<-exit
}

func hashLeaf(data []byte) common.Uint256 {
	tmp := append([]byte{0}, data...)
	return sha256.Sum256(tmp)
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

func leafvToAddArgs(leafs []common.Uint256) []interface{} {
	addargs := make([]interface{}, 0, len(leafs))

	for i := range leafs {
		addargs = append(addargs, hex.EncodeToString(leafs[i][:]))
	}

	return addargs
}

func getVerifyArgs(leaf common.Uint256) []interface{} {
	vargs := make([]interface{}, 1, 1)
	vargs[0] = hex.EncodeToString(leaf[:])
	return vargs
}

func clean() {
	os.RemoveAll("merkletree.db")
}

func printLeafs(prefix string, leafs []common.Uint256) {
	for i := range leafs {
		fmt.Printf("%s[%d]: %x\n", prefix, i, leafs[i])
	}
}

func HashFromHexString(s string) common.Uint256 {
	hx, err := common.HexToBytes(s)
	if err != nil {
		panic(err)
	}
	res, err := common.Uint256ParseFromBytes(hx)
	if err != nil {
		panic(err)
	}
	return res
}

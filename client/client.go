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
	N uint32 = 256
)

func testVerify(client *RpcClient, tree *merkle.CompactMerkleTree, verifych <-chan verifyArg) {
	for {
		select {
		case p := <-verifych:
			time.Sleep(time.Second * 5)
			leafs := p.Leafs
			root := p.Root
			m := p.M
			for k := uint32(0); k < uint32(N); k++ {
				for x := int(k); x >= 0; x-- {
					fmt.Printf("Verfiy leaf %x, root %x, treeSize: %d\n", leafs[x], root[k], k+1+N*m)
					vargs := getVerifyArgs(leafs[x], root[k], k+1+N*m)
					res, err := client.sendRpcRequest(client.GetNextQid(), "verify", []interface{}{vargs})
					if err != nil {
						fmt.Printf("Verify Failed %s\n", err)
						return
					}
					fmt.Printf("Verify Success %s\n", string(res))
				}
			}
		}
	}
}

func main() {
	defer clean()
	testUrl := "http://127.0.0.1:32339"
	client := NewRpcClient(testUrl)
	if true {
		numbatch := uint32(8500)
		verifychan := make(chan verifyArg, numbatch)
		tree := MerkleInit()
		//var alladdargs []string
		//alladdargs := make([]string, numbatch, numbatch)

		go testVerify(client, tree, verifychan)

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
			getleafvroot(leafs, tree, false)
			//printLeafs("root", root)
			//tree.AppendHash(leafs[i])
			addArgs := leafvToAddArgs(leafs)
			//generateConArgs(leafs)
			//alladdargs = append(alladdargs, addArgs)
			//alladdargs[m] = addArgs
			//res, err := client.sendRpcRequest(client.GetNextQid(), "batch_add", []interface{}{alladdargs[m]})

			_, err := client.sendRpcRequest(client.GetNextQid(), "batch_add", []interface{}{addArgs})
			if err != nil {
				fmt.Printf("Add Error: %s\n", err)
				return
			}

			if (m*N)%(256*100) == 0 {
				fmt.Printf("root %x, treeSize %d\n", tree.Root(), tree.TreeSize())
			}

			//fmt.Printf("Add Success %s\n", string(res))

			// after tx ok.
			//_ = verifyArg{
			//	Leafs: leafs,
			//	Root:  root,
			//	M:     m,
			//}
			//verifychan <- varg
		}
		fmt.Printf("prepare args done\n")
		fmt.Printf("root %x, treeSize %d\n", tree.Root(), tree.TreeSize())

		/*
			t0 := time.Now()
			for m := uint32(0); m < numbatch; m++ {
				res, err := client.sendRpcRequest(client.GetNextQid(), "batch_add", []interface{}{alladdargs[m]})
				if err != nil {
					fmt.Printf("Add Error: %s\n", err)
					return
				}

				fmt.Printf("Add Success %s\n", string(res))
			}

			fmt.Println("duration", time.Since(t0))
		*/
	}

	waitToExit()
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

func leafvToAddArgs(leafs []common.Uint256) string {
	sink := common.NewZeroCopySink(nil)
	for i := range leafs {
		sink.WriteHash(leafs[i])
	}

	return hex.EncodeToString(sink.Bytes())
}

func generateConArgs(leafs []common.Uint256) {
	for i := range leafs {
		fmt.Printf("bytearray:%x,", leafs[i])
	}
}

func printLeafs(prefix string, leafs []common.Uint256) {
	for i := range leafs {
		fmt.Printf("%s[%d]: %x\n", prefix, i, leafs[i])
	}
}

func getVerifyArgs(leaf common.Uint256, root common.Uint256, treeSize uint32) string {
	sink := common.NewZeroCopySink(nil)
	sink.WriteHash(leaf)
	sink.WriteHash(root)
	sink.WriteUint32(treeSize)
	return hex.EncodeToString(sink.Bytes())
}

//=================

func GenerateAddArgs(start uint32, N uint32) string {
	//N := uint32(3)
	//leafs := make([]common.Uint256, 0)
	//for i := uint32(1); i <= N; i++ {
	//	x := byte(i)
	//	leafs = append(leafs, hashLeaf([]byte{x}))
	//}

	//N := uint32(2)
	//start := uint32(1)
	leafs := make([]common.Uint256, 0)
	for i := uint32(start); i < start+N; i++ {
		x := byte(i)
		leafs = append(leafs, hashLeaf([]byte{x}))
	}

	sink := common.NewZeroCopySink(nil)
	for i := range leafs {
		fmt.Printf("hash[%d]: %x\n", i, leafs[i])
		sink.WriteHash(leafs[i])
	}
	fmt.Printf("\n")

	store, _ := merkle.NewFileHashStore("merkletree.db", 0)
	tree := merkle.NewTree(0, nil, store)
	if tree.Root() != sha256.Sum256(nil) {
		panic("root error")
	}
	for i := range leafs {
		tree.AppendHash(leafs[i])
	}

	fmt.Printf("\n")

	fmt.Printf("root: %x\n", tree.Root())

	return hex.EncodeToString(sink.Bytes())
}

func GenerateVerifyArgs() string {
	N := uint32(2)
	leafs := make([]common.Uint256, 0)
	for i := uint32(1); i <= N; i++ {
		x := byte(i)
		leafs = append(leafs, hashLeaf([]byte{x}))
	}

	sink := common.NewZeroCopySink(nil)

	for i := range leafs {
		fmt.Printf("bytearray:%x,", leafs[i])
		sink.WriteHash(leafs[i])
	}
	fmt.Printf("\n")
	sink.WriteUint32(N)

	return hex.EncodeToString(sink.Bytes())
}

func clean() {
	os.RemoveAll("merkletree.db")
}

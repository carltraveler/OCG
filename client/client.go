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
	"sync/atomic"
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

func main() {
	testUrl := "http://127.0.0.1:32339"
	client := NewRpcClient(testUrl)

	//addargs := GenerateAddArgs()
	//res, err := client.sendRpcRequest(client.GetNextQid(), "batch_add", []interface{}{addargs})
	//if err != nil {
	//	fmt.Printf("%s\n", err)
	//	return
	//}
	//msg := string(res)
	//fmt.Printf("%s\n", msg)

	verifyargs := GenerateVerifyArgs()
	//res, err := client.sendRpcRequest(client.GetNextQid(), "verify", []interface{}{verifyargs})
	res, err := client.sendRpcRequest(client.GetNextQid(), "verify", []interface{}{verifyargs})
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	msg := string(res)
	fmt.Printf("%s\n", msg)

	clean()
}

func hashLeaf(data []byte) common.Uint256 {
	tmp := append([]byte{0}, data...)
	return sha256.Sum256(tmp)
}

func GenerateAddArgs() string {
	N := uint32(3)
	leafs := make([]common.Uint256, 0)
	for i := uint32(1); i <= N; i++ {
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
	N := uint32(3)
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

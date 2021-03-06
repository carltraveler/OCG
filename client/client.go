package main

import "fmt"

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/merkle"
)

//JsonRpc version
const JSON_RPC_VERSION = "2.0"

//JsonRpcRequest object in rpc
type JsonRpcRequest struct {
	Version string   `json:"jsonrpc"`
	Id      string   `json:"id"`
	Method  string   `json:"method"`
	Params  RpcParam `json:"params"`
}

//JsonRpcResponse object response for JsonRpcRequest
type JsonRpcBatchAddResponse struct {
	Id     string `json:"id"`
	Error  int64  `json:"error"`
	Desc   string `json:"desc"`
	Result string `json:"result"`
}

type JsonRpcVerifyResponse struct {
	Id     string       `json:"id"`
	Error  int64        `json:"error"`
	Desc   string       `json:"desc"`
	Result VerifyResult `json:"result"`
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
func (this *RpcClient) sendRpcRequest(qid, method string, params RpcParam) (interface{}, error) {
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

	if method == "batchAdd" {
		rpcRsp := &JsonRpcBatchAddResponse{}
		err = json.Unmarshal(body, rpcRsp)
		if err != nil {
			return nil, fmt.Errorf("json.Unmarshal JsonRpcResponse:%s error:%s", body, err)
		}
		if rpcRsp.Error != 0 {
			return nil, fmt.Errorf("JsonRpcResponse error code:%d desc:%s result:%s", rpcRsp.Error, rpcRsp.Desc, rpcRsp.Result)
		}

		return nil, nil
	} else if method == "verify" {
		//fmt.Printf("response:\n%s", string(body))
		rpcRsp := &JsonRpcVerifyResponse{}
		err = json.Unmarshal(body, rpcRsp)
		if rpcRsp.Error != 0 {
			return nil, fmt.Errorf("JsonRpcResponse error code:%d desc:%s", rpcRsp.Error, rpcRsp.Desc)
		}
		return &rpcRsp.Result, nil
	}

	return nil, errors.New("error method")
}

func verifyleaf(client *RpcClient, leafs []common.Uint256, v bool) {
	for i := uint32(0); i < uint32(len(leafs)); i++ {
		vargs := getVerifyArgs(leafs[i])
		res, err := client.sendRpcRequest(client.GetNextQid(), "verify", vargs)
		if err != nil {
			fmt.Printf("Verify Failed %s\n", err)
			panic("xxx")
		}

		vres, ok := res.(*VerifyResult)
		if !ok {
			panic("error type")
		}
		//if v {
		//	err = Verify(vres, leafs[i])
		//	if err != nil {
		//		panic(err)
		//	}
		//}
		fmt.Printf("success %v\n", vres.TreeSize)
	}
}

func sendtx() {
	testUrl := "http://127.0.0.1:32339"
	//testUrl := "http://127.0.0.1:32338"
	//testUrl := "http://127.0.0.1:8080"
	//testUrl := "https://attestation.ont.io"
	client := NewRpcClient(testUrl)
	SystemOut = false
	wg.Add(1)
	defer wg.Done()

	fmt.Printf("prepare args\n")
	for ; m < numbatch; m++ {
		if SystemOut {
			break
		}

		if m%1000 == 0 {
			fmt.Printf("send %d\n", m)
		}
		var leafs []common.Uint256
		leafs = GenerateLeafv(uint32(0)+N*m, N)
		addArgs := leafvToAddArgs(leafs)
		if verify {
			verifyleaf(client, leafs, true)
		} else {
			_, err := client.sendRpcRequest(client.GetNextQid(), "batchAdd", addArgs)
			if err != nil {
				if k == 0 {
					fmt.Printf("Add Error: %s, added num: %d\n", err, 0)
				} else {
					fmt.Printf("Add Error: %s, added num: %d\n", err, k*m)
				}
				panic("xxxx")
			}
			k++
		}
	}

	fmt.Printf("sendDone.")

}

var (
	k         uint32 = uint32(0)
	m         uint32 = uint32(0)
	wg        sync.WaitGroup
	SystemOut bool = true
)

var (
	N        uint32 = 1
	numbatch uint32 = 100000
	verify   bool   = false
)

func main() {
	defer clean()
	err := InitSigner()
	if err != nil {
		panic(err)
	}
	go sendtx()
	fmt.Printf("ready to done. use ctrl+c\n")
	waitToExit()
}

func waitToExit() {
	exit := make(chan bool, 0)
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sc {
			SystemOut = true
			wg.Wait()
			fmt.Printf("added num: %d, tatal: %d\n", k*N, m*N)

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

type RpcParam struct {
	PubKey   string   `json:"pubKey"`
	Sigature string   `json:"signature"`
	Hashes   []string `json:"hashes"`
}

func leafvToAddArgs(leafs []common.Uint256) RpcParam {
	leafargs := make([]string, 0, len(leafs))

	for i := range leafs {
		leafargs = append(leafargs, hex.EncodeToString(leafs[i][:]))
	}

	sigData, err := DefSigner.Sign(leafs[0][:])
	if err != nil {
		panic(err)
	}

	addargs := RpcParam{
		PubKey:   hex.EncodeToString(keypair.SerializePublicKey(DefSigner.GetPublicKey())),
		Sigature: hex.EncodeToString(sigData),
		Hashes:   leafargs,
	}

	err = signature.Verify(DefSigner.GetPublicKey(), leafs[0][:], sigData)
	if err != nil {
		panic(err)
	}

	return addargs
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

func getVerifyArgs(leaf common.Uint256) RpcParam {
	leafs := make([]string, 1, 1)
	leafs[0] = hex.EncodeToString(leaf[:])

	vargs := RpcParam{
		PubKey: hex.EncodeToString(keypair.SerializePublicKey(DefSigner.GetPublicKey())),
		Hashes: leafs,
	}

	return vargs
}

func clean() {
	os.RemoveAll("merkletree.db")
}

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

var DefSigner sdk.Signer

func InitSigner() error {
	DefSdk := sdk.NewOntologySdk()
	wallet, err := DefSdk.OpenWallet("wallet.dat")
	if err != nil {
		return fmt.Errorf("error in OpenWallet:%s\n", err)
	}

	DefSigner, err = wallet.GetAccountByAddress("APHNPLz2u1JUXyD8rhryLaoQrW46J3P6y2", []byte("123456"))
	if err != nil {
		return fmt.Errorf("error in GetDefaultAccount:%s\n", err)
	}

	return nil
}

func Verify(vres *VerifyResult, leaf common.Uint256) error {
	verify := merkle.NewMerkleVerifier()
	err := verify.VerifyLeafHashInclusion(leaf, vres.Index, vres.Proof, vres.Root, vres.TreeSize)
	if err != nil {
		return err
	}

	return nil
}

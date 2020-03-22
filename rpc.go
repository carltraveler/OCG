/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

// Package rpc provides functions to for rpc server call
package main

import (
	"encoding/json"
	//"fmt"
	"github.com/ontio/ontology/common/log"
	"io"
	"net/http"
)

const MAX_REQUEST_BODY_SIZE = 1 << 20

//JsonRpcRequest object in rpc
type JsonRpcRequest struct {
	Version string   `json:"jsonrpc"`
	Id      string   `json:"id"`
	Method  string   `json:"method"`
	Params  RpcParam `json:"params"`
}

type RpcParam struct {
	PubKey   string   `json:"pubKey"`
	Sigature string   `json:"signature"`
	Hashes   []string `json:"hashes"`
}

// this is the function that should be called in order to answer an rpc call
// should be registered like "http.HandleFunc("/", httpjsonrpc.Handle)"
func RpcHandle(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("content-type", "application/json;charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		return
	}
	//JSON RPC commands should be POSTs
	if r.Method != "POST" {
		log.Error("HTTP JSON RPC Handle - Method!=\"POST\"")
		return
	}
	//check if there is Request Body to read
	if r.Body == nil {
		log.Error("HTTP JSON RPC Handle - Request body is nil")
		return
	}

	var request JsonRpcRequest
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, MAX_REQUEST_BODY_SIZE))
	err := decoder.Decode(&request)
	if err != nil {
		log.Error("HTTP JSON RPC Handle - json.Unmarshal: ", err)
		return
	}

	var response map[string]interface{}

	if request.Method == "verify" {
		response = rpcVerify(&request.Params)
	} else if request.Method == "batchAdd" {
		response = rpcBatchAdd(&request.Params)
	} else {
		log.Warn("HTTP JSON RPC Handle - No function to call for ", request.Method)
		response = responsePack(INVALID_PARAM, "wrong Method name.only verify or batchAdd")
	}

	data, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"error":   response["error"],
		"desc":    response["desc"],
		"result":  response["result"],
		"id":      request.Id,
	})

	if err != nil {
		log.Error("HTTP JSON RPC Handle - json.Marshal: ", err)
		return
	}
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("content-type", "application/json;charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

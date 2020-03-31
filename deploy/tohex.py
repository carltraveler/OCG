#!/usr/env/bin python3
import binascii
contract_binary = 'a.wasm'  # default binary name a.out
with open(contract_binary, 'rb') as binaryfile:
        codedata = binaryfile.read()

data_str = binascii.hexlify(codedata).decode('ascii')
with open(contract_binary + '.str', 'w') as out_file:
    out_file.write(data_str)

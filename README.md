# aesgcm

A simple utility to encrypt / decrypt data with AES-256 GCM. 

## Usage

```
aesgcm
  -d    decrypt a file
  -e    encrypt a file
  -g    generate a new key
  -i string
        input file (default "-")
  -k string
        key for encryption/decryption
  -l int
        generate a new key with the given length (default 32)
  -n string
        nonce for decryption
  -o string
        output file (default "-")
```
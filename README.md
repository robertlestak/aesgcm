# aesgcm

A simple utility to encrypt / decrypt data with AES-256 GCM. 

## Usage

```
aesgcm
  -dec
        Decrypt a file
  -enc
        Encrypt a file
  -in string
        Input file (default "-")
  -k string
        Key
  -len int
        Generate a new key with the given length (default 32)
  -new
        Generate a new key
  -nonce string
        Nonce
  -out string
        Output file (default "-")
```
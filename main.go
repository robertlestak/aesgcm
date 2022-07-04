package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func GenerateNewAESKey(len int) ([]byte, error) {
	key := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func AesGcmEncrypt(key []byte, raw []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, raw, nil)
	return ciphertext, nonce, nil
}

func AesGcmDecrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	raw, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func readInputData(in string) ([]byte, error) {
	var raw []byte
	var err error
	if in == "-" || in == "" {
		raw, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
	} else {
		raw, err = ioutil.ReadFile(in)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func main() {
	flagNewKey := flag.Bool("g", false, "generate a new key")
	flagEncrypt := flag.Bool("e", false, "encrypt a file")
	flagDecrypt := flag.Bool("d", false, "decrypt a file")
	flagNewLength := flag.Int("l", 32, "generate a new key with the given length")
	flagKey := flag.String("k", "", "key for encryption/decryption")
	flagNonce := flag.String("n", "", "nonce for decryption")
	flagInput := flag.String("i", "-", "input file")
	flagOutput := flag.String("o", "-", "output file")
	flag.Parse()
	if *flagNewKey {
		key, err := GenerateNewAESKey(*flagNewLength)
		if err != nil {
			panic(err)
		}
		fmt.Println(hex.EncodeToString(key))
		return
	}
	if *flagEncrypt {
		if *flagKey == "" {
			panic("No key")
		}
		raw, err := readInputData(*flagInput)
		if err != nil {
			panic(err)
		}
		kd, err := hex.DecodeString(*flagKey)
		if err != nil {
			panic(err)
		}
		ciphertext, nonce, err := AesGcmEncrypt(kd, raw)
		if err != nil {
			panic(err)
		}
		nonceEnc := hex.EncodeToString(nonce)
		ciphertextEnc := hex.EncodeToString(ciphertext)
		if *flagOutput == "-" || *flagOutput == "" {
			fmt.Println("nonce: " + nonceEnc)
			fmt.Println("cipher: " + ciphertextEnc)
		} else {
			fmt.Println("nonce: " + nonceEnc)
			if err := ioutil.WriteFile(*flagOutput, []byte(ciphertextEnc), 0644); err != nil {
				panic(err)
			}
		}
		return
	}
	if *flagDecrypt {
		if *flagKey == "" {
			panic("No key")
		}
		kd, err := hex.DecodeString(*flagKey)
		if err != nil {
			panic(err)
		}
		if *flagInput == "" {
			panic("No input string")
		}
		if *flagNonce == "" {
			panic("No nonce")
		}
		nonce, err := hex.DecodeString(*flagNonce)
		if err != nil {
			panic(err)
		}
		ind, err := readInputData(*flagInput)
		if err != nil {
			panic(err)
		}
		cd, err := hex.DecodeString(strings.TrimSpace(string(ind)))
		if err != nil {
			panic(err)
		}
		plaintext, err := AesGcmDecrypt(kd, cd, nonce)
		if err != nil {
			panic(err)
		}
		if *flagOutput == "-" || *flagOutput == "" {
			fmt.Print(string(plaintext))
		} else {
			if err := ioutil.WriteFile(*flagOutput, plaintext, 0644); err != nil {
				panic(err)
			}
		}
		return
	}
	// print default
	flag.PrintDefaults()
}

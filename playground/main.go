package main

import (
	// "github.com/tyler-smith/go-bip32"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/anyproto/go-slip10"
	"github.com/tyler-smith/go-bip39"
)

func pem_encode_public(key ed25519.PublicKey) {
}

func main() {
	mnemonic := "include pear escape sail spy orange cute despair witness trouble sleep torch wire burst unable brass expose fiction drift clock duck oxygen aerobic already"
	password := "bob"
	seed := bip39.NewSeed(mnemonic, password)

	node, err := slip10.DeriveForPath("m/0'/1'", seed)
	if err != nil {
		panic(err)
	}

	pub, priv := node.Keypair()

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	pemb := pem.EncodeToMemory(block)
	fmt.Printf("%s\n", string(pemb))

	_ = pub
	// _ = node.PublicKeyWithPrefix()
	// fmt.Printf("%x\n", pub)

	// pubK := node.PublicKeyWithPrefix()

	// // prints 001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187
	// fmt.Printf("%x\n", pubK)

	// // Generate a mnemonic for memorization or user-friendly seeds
	// entropy, _ := bip39.NewEntropy(256)
	// mnemonic, _ := bip39.NewMnemonic(entropy)

	// // Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	// seed := bip39.NewSeed(mnemonic, "Secret Passphrase")

	// masterKey, _ := bip32.NewMasterKey(seed)
	// publicKey := masterKey.PublicKey()

	// // Display mnemonic and keys
	// fmt.Println("Mnemonic: ", mnemonic)
	// fmt.Println("Master private key: ", masterKey)
	// fmt.Println("Master public key: ", publicKey)
}

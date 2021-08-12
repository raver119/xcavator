package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"github.com/raver119/xcavator/embedded"
	"io/ioutil"
	"log"
)

func main() {
	path := flag.String("path", "", "Path tho the file to be encrypted")
	keyLength := flag.Int("bits", 1024, "Encryption key lengths.Multiple of 1024. I.. 1024, 2048, 3072 or 4096 etc")
	aes := flag.Int("aes", 256, "AES cipher. Valid values are: 128, 192 and 256")
	flag.Parse()

	if *aes != 128 && *aes != 192 && *aes != 256 {
		log.Fatalf("AES cipher must be on of [128, 192, 256]")
	}

	if *keyLength%1024 > 0 {
		log.Fatalf("Bits must be multiple of 1024")
	}

	if !embedded.FileExits(*path) {
		log.Fatalf("Path [%v] doesn't exist", *path)
	}

	xcavator, err := embedded.NewEncrypted(*path, embedded.AES256)
	if err != nil {
		log.Fatalf("Failed to create Xcavator instance: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, *keyLength)
	if err != nil {
		log.Fatalf("Failed to create keys: %v", err)
	}

	b, err := ioutil.ReadFile(*path)
	if err != nil {
		log.Fatalf("Failed to read source file: %v", err)
	}

	b, err = xcavator.Encrypt(b, &key.PublicKey)
	if err != nil {
		log.Fatalf("Failed to encrypt file: %v", err)
	}

	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pbk, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("Failed to serialize public key")
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pbk,
	})

	log.Printf("PrivateKey: %v", base64.StdEncoding.EncodeToString(privBytes))
	log.Printf("PublicKey: %v", base64.StdEncoding.EncodeToString(pubBytes))
	log.Printf("Encrypted Base64 file: %v", base64.StdEncoding.EncodeToString(b))
	log.Printf("Encrypted raw file: %v", string(b))
}

package embedded

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
)


type Impl struct {
	path string
	algo EncryptionAlgorithm
	raw bool
	lock sync.RWMutex
}

// NewEncrypted function creates new Xcavator instance
func NewEncrypted(path string, algo EncryptionAlgorithm) (x *Impl, err error) {
	x, err = NewRaw(path)
	if err != nil {
		return
	}

	x.algo = algo
	x.raw = false
	return
}

func NewRaw(path string) (x *Impl, err error)  {
	x = new(Impl)
	x.path = path
	x.raw = true

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}

	return
}

// Forget function overwrites stored data
func (x *Impl) Forget() (err error) {
	x.lock.Lock()
	defer x.lock.Unlock()

	// try to remove file
	err = os.Remove(x.path)

	x.path = ""
	x.algo = AES128

	return
}

// Encrypt method encrypts input bytes and returns Message with all fields defined
// Payload will be encrypted with rng-generated key using AES CTR mode, AES key will
// be encrypted with provided RSA PublicKey
func (x *Impl) Encrypt(input []byte, key *rsa.PublicKey) (e []byte, err error) {
	aesKey := make([]byte, keyLength(x.algo))
	hmacKey :=  make([]byte, keyLength(x.algo))
	read, err := rand.Reader.Read(aesKey)
	if err != nil {
		return nil, err
	}

	read, err = rand.Reader.Read(hmacKey)
	if err != nil {
		return nil, err
	}

	if read != keyLength(x.algo) {
		return nil, fmt.Errorf("failed to get enough random values for the key")
	}

	encrypted, iv, err := encrypt(input, aesKey, hmacKey)
	if err != nil {
		return nil, err
	}

	encAesKey, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, key, aesKey, nil)
	if err != nil {
		return nil, err
	}

	encHmacKey, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, key, hmacKey, nil)
	if err != nil {
		return nil, err
	}

	msg := Message{
		Key:     base64.StdEncoding.EncodeToString(encAesKey),
		Hash: 	 base64.StdEncoding.EncodeToString(encHmacKey),
		Algo:    x.algo,
		Payload: base64.StdEncoding.EncodeToString(encrypted),
		IV:      base64.StdEncoding.EncodeToString(iv),
	}

	return msg.ToJson(), err
}

// Put function encrypts target data
func (x *Impl) Put(target interface{}, key *rsa.PublicKey) (err error) {
	x.lock.Lock()
	defer x.lock.Unlock()

	b, err := json.Marshal(target)
	if err != nil {
		return err
	}

	var encrypted []byte

	if x.raw {
		encrypted, err = json.Marshal(target)
		if err != nil {
			return err
		}
	} else {
		encrypted, err = x.Encrypt(b, key)
		if err != nil {
			return err
		}
	}

	err = ioutil.WriteFile(x.path, encrypted, os.FileMode(int(0755)))
	return
}

// Extract function reads Message file from the path argument and decrypts it
func (x *Impl) Extract(target interface{}, key *rsa.PrivateKey) (err error) {
	x.lock.RLock()
	defer x.lock.RUnlock()

	if x.path == "" {
		return fmt.Errorf("it's impossible to extract data after Forget() was called")
	}

	var raw []byte
	raw, err = ioutil.ReadFile(x.path)
	if err != nil {
		return
	}

	if key == nil && !x.raw {
		return fmt.Errorf("no key was provided")
	}

	if x.raw {
		// ?
	} else {
		var message Message
		err = json.Unmarshal(raw, &message)
		if err != nil {
			return err
		}

		if message.Key == "" || message.IV == "" || message.Hash == "" || message.Payload == "" {
			return fmt.Errorf("Message structure seems to have empty fields")
		}

		var aesKey []byte
		var hmacKey []byte
		encAesKey, err := base64.StdEncoding.DecodeString(message.Key)
		if err != nil {
			return err
		}

		encHmacKey, err := base64.StdEncoding.DecodeString(message.Hash)
		if err != nil {
			return err
		}

		// decrypt key
		aesKey, err = rsa.DecryptOAEP(crypto.SHA256.New(), rand.Reader, key, encAesKey, nil)
		if err != nil {
			return err
		}

		// decrypt hash
		hmacKey, err = rsa.DecryptOAEP(crypto.SHA256.New(), rand.Reader, key, encHmacKey, nil)
		if err != nil {
			return err
		}

		payload, err := base64.StdEncoding.DecodeString(message.Payload)
		if err != nil {
			return err
		}

		iv, err := base64.StdEncoding.DecodeString(message.IV)
		if err != nil {
			return err
		}

		// now, use this key to decrypt
		raw, err = decrypt(payload, aesKey, iv, hmacKey)
		if err != nil {
			return err
		}
	}

	err = json.Unmarshal(raw, target)
	return
}

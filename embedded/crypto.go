package embedded

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
)

const BUFFER_SIZE int = 1024

func decrypt(encrypted, keyAes, iv, keyHmac []byte) (output []byte, err error) {
	// last 256 bits must be a hash
	hashLength := 256 / 8
	hashOffset := len(encrypted) - hashLength
	hash := encrypted[hashOffset:]

	vhmac := hmac.New(sha256.New, keyHmac)
	vaes, err := aes.NewCipher(keyAes)
	if err != nil {
		return nil, err
	}

	ctr := cipher.NewCTR(vaes, iv)

	bufIn := bytes.NewBuffer(encrypted[0:hashOffset])
	bufOut := bytes.NewBuffer([]byte{})
	buf := make([]byte, BUFFER_SIZE)
	for {
		n, err := bufIn.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		inBuf := make([]byte, n)
		outBuf := make([]byte, n)
		copy(inBuf, buf)

		vhmac.Write(inBuf)
		ctr.XORKeyStream(outBuf, inBuf)
		bufOut.Write(outBuf)

		if err == io.EOF {
			break
		}
	}

	vhmac.Write(iv)
	exp := vhmac.Sum(nil)

	if !reflect.DeepEqual(exp, hash) {
		return nil, fmt.Errorf("hmac signature doesn't match")
	}

	return bufOut.Bytes(), err
}

func encrypt(input, keyAes, keyHmac []byte) (output []byte, iv []byte, err error) {
	bufIn := bytes.NewBuffer(input)
	bufOut := bytes.NewBuffer(output)
	iv = make([]byte, 16) // iv size is constant equal to aes block size
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	vaes, err := aes.NewCipher(keyAes)
	if err != nil {
		return nil, nil, err
	}

	ctr := cipher.NewCTR(vaes, iv)
	vhmac := hmac.New(sha256.New, keyHmac)

	buf := make([]byte, BUFFER_SIZE)
	for {
		n, err := bufIn.Read(buf)
		if err != nil && err != io.EOF {
			return nil, nil, err
		}

		outBuf := make([]byte, n)
		ctr.XORKeyStream(outBuf, buf[:n])
		vhmac.Write(outBuf)

		bufOut.Write(outBuf)

		if err == io.EOF {
			break
		}
	}

	vhmac.Write(iv)

	// last 256 bits is a hash
	bufOut.Write(vhmac.Sum(nil))

	return bufOut.Bytes(), iv, err
}

func keyLength(algo EncryptionAlgorithm) int {
	return algoBits(algo) / 8
}
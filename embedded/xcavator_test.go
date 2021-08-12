package embedded

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	rand2 "math/rand"
	"os"
	"testing"
)

type credentials struct {
	Filed1 string `json:"filed1"`
	Field2 int64  `json:"field2"`
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand2.Intn(len(letters))]
	}
	return string(b)
}

func TestImpl_Encrypted(t *testing.T) {
	lengths := []int{8, 32, 1024, 5000, 15000}
	keys := []int{1024, 2048, 3072, 4096}
	algorithms := []EncryptionAlgorithm{AES128, AES192, AES256}

	for _, length := range lengths {
		for _, bits := range keys {
			for _, algo := range algorithms {
				t.Run(fmt.Sprintf("%v RSA%v_AES%v", length, bits, algoBits(algo)), func(t *testing.T) {
					key, err := rsa.GenerateKey(rand.Reader, bits)
					require.NoError(t, err)

					src := credentials{
						Filed1: randomString(length),
						Field2: 189,
					}

					file, err := ioutil.TempFile(os.TempDir(), "")
					require.NoError(t, err)

					enc, err := NewEncrypted(file.Name(), algo)
					require.NoError(t, err)

					require.NoError(t, enc.Put(src, &key.PublicKey))

					dec, err := NewEncrypted(file.Name(), algo)
					require.NoError(t, err)

					var xtrct credentials
					require.NoError(t, dec.Extract(&xtrct, key))
					require.Equal(t, src, xtrct)
				})
			}
		}
	}
}

func TestImpl_Raw(t *testing.T) {
	src := credentials{
		Filed1: randomString(16),
		Field2: 189,
	}

	file, err := ioutil.TempFile(os.TempDir(), "")
	require.NoError(t, err)

	x, err := NewRaw(file.Name())
	require.NoError(t, err)

	require.NoError(t, x.Put(src, nil))

	var xtrct credentials
	require.NoError(t, x.Extract(&xtrct, nil))
	require.Equal(t, src, xtrct)
}
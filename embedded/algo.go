package embedded

type EncryptionAlgorithm int

const (
	AES128 EncryptionAlgorithm = iota
	AES192
	AES256
)

func algoBits(algo EncryptionAlgorithm) int {
	switch algo {
	case AES128:
		return 128
	case AES192:
		return 192
	case AES256:
		return 256
	default:
		return 0
	}
}
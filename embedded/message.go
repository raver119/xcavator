package embedded

import "encoding/json"

type Message struct {
	Key     string              `json:"key"`
	Hash    string				`json:"hash"`
	Algo    EncryptionAlgorithm `json:"algo"`
	Payload string              `json:"payload"`
	IV      string              `json:"iv"`
}

func (m Message) ToJson() (b []byte) {
	b, _ = json.Marshal(m)
	return
}

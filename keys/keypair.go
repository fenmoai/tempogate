package keys

import "time"

type Keypair struct {
	Kid        string
	Alg        string
	PrivatePEM []byte
	PublicPEM  []byte
	CreatedAt  time.Time
}

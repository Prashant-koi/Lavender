package natsx

import (
	"fmt"

	nats "github.com/nats-io/nats.go"
)

func Connect(url string) (*nats.Conn, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}

	return nc, nil
}

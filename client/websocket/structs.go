package websocket

import (
	"fmt"

	"github.com/dgrr/fastws"
)

type Client struct {
	*fastws.Conn
	P         [32]byte
	Nonce     [12]byte
	HashKey   [32]byte
	SessionID string
}

func NewClient(port string) (*Client, error) {
	conn, err := fastws.Dial(fmt.Sprintf("ws://localhost:%s", port))
	if err != nil {
		return nil, err
	}

	return &Client{Conn: conn}, nil
}
